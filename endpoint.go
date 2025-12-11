package connet

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/statusc"
	"github.com/quic-go/quic-go"
)

type EndpointStatus struct {
	Status statusc.Status
	Peer   PeerStatus
}

type endpoint interface {
	runPeerErr(ctx context.Context) error
	runAnnounceErr(ctx context.Context, conn *quic.Conn, directAddrs *notify.V[advertiseAddrs], firstReport func(error)) error
}

type clientEndpoint struct {
	client        *Client
	ep            endpoint
	clientCleanup func()

	ctx       context.Context
	ctxCancel context.CancelCauseFunc
	closer    chan struct{}

	onlineReport func(err error)
	connStatus   atomic.Value

	logger *slog.Logger
}

// a client endpoint could close when:
//   - the user cancels the incomming context. This could happen while setting up the endpoint too.
//   - the user calls Close explicitly.
//   - the parent client is closing, so it calls close on the endpoint too. Session might be closing at the same time.
//   - an error happens in runPeer
//   - a terminal error happens in runAnnounce
func newClientEndpoint(ctx context.Context, cl *Client, ep endpoint, logger *slog.Logger, clientCleanup func()) (*clientEndpoint, error) {
	ctx, ctxCancel := context.WithCancelCause(ctx)
	cep := &clientEndpoint{
		client:        cl,
		ep:            ep,
		clientCleanup: clientCleanup,

		ctx:       ctx,
		ctxCancel: ctxCancel,
		closer:    make(chan struct{}),

		logger: logger,
	}
	cep.connStatus.Store(statusc.NotConnected)
	context.AfterFunc(ctx, cep.cleanup)

	errCh := make(chan error)
	var reportOnce sync.Once
	cep.onlineReport = func(err error) {
		reportOnce.Do(func() {
			if err != nil {
				errCh <- err
			}
			close(errCh)
		})
	}

	go cep.runPeer(ctx)
	go cep.runAnnounce(ctx)

	select {
	case <-ctx.Done():
		cep.ctxCancel(ctx.Err())
		return nil, ctx.Err()
	case err := <-errCh:
		if err != nil {
			cep.ctxCancel(err)
			return nil, err
		}
	}

	return cep, nil
}

func (e *clientEndpoint) status() statusc.Status {
	return e.connStatus.Load().(statusc.Status)
}

func (e *clientEndpoint) close() error {
	e.ctxCancel(net.ErrClosed)
	<-e.closer
	return nil
}

func (e *clientEndpoint) runPeer(ctx context.Context) {
	if err := e.ep.runPeerErr(ctx); err != nil {
		e.ctxCancel(err)
	}
}

func (e *clientEndpoint) runAnnounce(ctx context.Context) {
	err := e.client.currentSession.Listen(ctx, func(sess *session) error {
		if sess != nil {
			go e.runAnnounceSession(ctx, sess)
		}
		return nil
	})
	if err != nil {
		e.ctxCancel(err)
	}
}

func (e *clientEndpoint) runAnnounceSession(ctx context.Context, sess *session) {
	for {
		err := e.ep.runAnnounceErr(ctx, sess.conn, sess.addrs, func(err error) {
			if err == nil {
				e.connStatus.Store(statusc.Connected)
			}
			e.onlineReport(err)
		})
		e.connStatus.CompareAndSwap(statusc.Connected, statusc.Reconnecting)

		switch {
		case err == nil:
		case errors.Is(err, context.Canceled):
			return
		case sess.conn.Context().Err() != nil:
			return
		default:
			e.logger.Debug("announce stopped", "err", err)
		}
	}
}

func (e *clientEndpoint) cleanup() {
	defer close(e.closer)
	defer e.connStatus.Store(statusc.Disconnected)
	e.clientCleanup()
}

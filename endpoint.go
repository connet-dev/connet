package connet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/slogc"
	"github.com/connet-dev/connet/statusc"
	"github.com/quic-go/quic-go"
)

type endpointStatus struct {
	Status statusc.Status
	StatusPeer
}

type endpointConfig struct {
	endpoint model.Endpoint
	role     model.Role
	route    model.RouteOption
}

type endpoint struct {
	client *Client
	cfg    endpointConfig
	peer   *peer

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
func newEndpoint(ctx context.Context, cl *Client, cfg endpointConfig, logger *slog.Logger) (*endpoint, error) {
	p, err := newPeer(cl.directServer, cl.addrs, cfg.route.AllowDirect(), logger)
	if err != nil {
		return nil, err
	}

	ctx, ctxCancel := context.WithCancelCause(ctx)
	ep := &endpoint{
		client: cl,
		cfg:    cfg,
		peer:   p,

		ctx:       ctx,
		ctxCancel: ctxCancel,
		closer:    make(chan struct{}),

		logger: logger,
	}
	ep.connStatus.Store(statusc.NotConnected)
	context.AfterFunc(ctx, ep.cleanup)

	errCh := make(chan error)
	var reportOnce sync.Once
	ep.onlineReport = func(err error) {
		if err == nil {
			ep.connStatus.Store(statusc.Connected)
		}
		reportOnce.Do(func() {
			if err != nil {
				errCh <- err
			}
			close(errCh)
		})
	}

	go ep.runPeer(ctx)
	go ep.runSession(ctx)

	select {
	case <-ctx.Done():
		ep.ctxCancel(ctx.Err())
		return nil, ctx.Err()
	case err := <-errCh:
		if err != nil {
			ep.ctxCancel(err)
			return nil, err
		}
	}

	return ep, nil
}

func (ep *endpoint) status() (endpointStatus, error) {
	peerStatus, err := ep.peer.status()
	if err != nil {
		return endpointStatus{}, err
	}
	return endpointStatus{
		Status:     ep.connStatus.Load().(statusc.Status),
		StatusPeer: peerStatus,
	}, nil
}

func (ep *endpoint) close() error {
	ep.ctxCancel(net.ErrClosed)
	<-ep.closer
	return nil
}

func (ep *endpoint) runPeer(ctx context.Context) {
	if err := ep.peer.run(ctx); err != nil {
		ep.ctxCancel(err)
	}
}

func (ep *endpoint) runSession(ctx context.Context) {
	err := ep.client.currentSession.Listen(ctx, func(sess *session) error {
		if sess != nil {
			go ep.runSessionAnnounce(ctx, sess)
		}
		return nil
	})
	if err != nil {
		ep.ctxCancel(err)
	}
}

func (ep *endpoint) runSessionAnnounce(ctx context.Context, sess *session) {
	for {
		err := ep.runSessionAnnounceErr(ctx, sess)
		ep.connStatus.CompareAndSwap(statusc.Connected, statusc.Reconnecting)

		switch {
		case err == nil:
		case errors.Is(err, context.Canceled):
			return
		case sess.conn.Context().Err() != nil:
			return
		default:
			ep.logger.Debug("announce stopped", "err", err)
		}
	}
}

func (ep *endpoint) runSessionAnnounceErr(ctx context.Context, sess *session) error {
	if ep.cfg.route.AllowRelay() {
		g := reliable.NewGroup(ctx)
		g.Go(reliable.Bind(sess.conn, ep.runAnnounce))
		g.Go(reliable.Bind(sess.conn, ep.runRelay))
		return g.Wait()
	}

	return ep.runAnnounce(ctx, sess.conn)
}

func (ep *endpoint) runAnnounce(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("announce open stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(ep.logger, "error closing announce stream", "err", err)
		}
	}()

	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(stream))

	g.Go(func(ctx context.Context) error {
		defer ep.logger.Debug("completed announce notify")
		return ep.peer.selfListen(ctx, func(peer *pbclient.Peer) error {
			ep.logger.Debug("updated announce", "direct", len(peer.Directs), "relays", len(peer.RelayIds))
			return proto.Write(stream, &pbclient.Request{
				Announce: &pbclient.Request_Announce{
					Endpoint: ep.cfg.endpoint.PB(),
					Role:     ep.cfg.role.PB(),
					Peer:     peer,
				},
			})
		})
	})

	g.Go(func(ctx context.Context) error {
		for {
			resp, err := pbclient.ReadResponse(stream)
			ep.onlineReport(err)
			if err != nil {
				return err
			}
			if resp.Announce == nil {
				return fmt.Errorf("announce unexpected response")
			}

			// TODO on server restart peers is reset and client loses active peers
			// only for them to come back at the next tick, with different ID
			ep.peer.setPeers(resp.Announce.Peers)
		}
	})

	return g.Wait()
}

func (ep *endpoint) runRelay(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("relay open stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(ep.logger, "error closing relay stream", "err", err)
		}
	}()

	if err := proto.Write(stream, &pbclient.Request{
		Relay: &pbclient.Request_Relay{
			Endpoint:          ep.cfg.endpoint.PB(),
			Role:              ep.cfg.role.PB(),
			ClientCertificate: ep.peer.clientCert.Leaf.Raw,
		},
	}); err != nil {
		return err
	}

	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(stream))

	g.Go(func(ctx context.Context) error {
		for {
			resp, err := pbclient.ReadResponse(stream)
			if err != nil {
				ep.onlineReport(err)
				return err
			}
			if resp.Relay == nil {
				return fmt.Errorf("relay unexpected response")
			}

			ep.peer.setRelays(resp.Relay.Relays)
		}
	})

	return g.Wait()
}

func (ep *endpoint) cleanup() {
	defer close(ep.closer)
	defer ep.connStatus.Store(statusc.Disconnected)

	switch ep.cfg.role {
	case model.Destination:
		ep.client.removeDestination(ep.cfg.endpoint)
	case model.Source:
		ep.client.removeSource(ep.cfg.endpoint)
	}
}

package connet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/connet-dev/connet/client"
	"github.com/quic-go/quic-go"
)

// Destination is type of endpoint that can receive remote connections and traffic.
// It implements net.Listener interface, so it
type Destination interface {
	Accept() (net.Conn, error)
	AcceptContext(ctx context.Context) (net.Conn, error)

	Addr() net.Addr
	Client() *Client
	Close() error
}

// DestinationConfig structure represents destination configuration. See [Client.DestinationConfig]
type DestinationConfig = client.DestinationConfig

// NewDestinationConfig creates a destination config for a given name. See [client.NewDestinationConfig]
var NewDestinationConfig = client.NewDestinationConfig

type Source interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)

	Client() *Client
	Close() error
}

// SourceConfig structure represents source configuration. See [Client.SourceConfig]
type SourceConfig = client.SourceConfig

// NewSourceConfig creates a destination config for a given name. See [client.NewSourceConfig]
var NewSourceConfig = client.NewSourceConfig

type clientDestination struct {
	*client.Destination
	*clientEndpoint
}

func newClientDestination(ctx context.Context, cl *Client, cfg DestinationConfig) (*clientDestination, error) {
	dst, err := client.NewDestination(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	ep, err := newClientEndpoint(ctx, cl, dst, func() {
		cl.removeDestination(cfg.Forward)
	})
	if err != nil {
		return nil, err
	}

	return &clientDestination{dst, ep}, nil
}

type clientSource struct {
	*client.Source
	*clientEndpoint
}

func newClientSource(ctx context.Context, cl *Client, cfg SourceConfig) (*clientSource, error) {
	src, err := client.NewSource(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	ep, err := newClientEndpoint(ctx, cl, src, func() {
		cl.removeSource(cfg.Forward)
	})
	if err != nil {
		return nil, err
	}

	return &clientSource{src, ep}, nil
}

type endpoint interface {
	RunPeer(ctx context.Context) error
	RunAnnounce(ctx context.Context, conn quic.Connection, directAddrs []netip.AddrPort, firstReport func(error)) error
}

type clientEndpoint struct {
	client        *Client
	ep            endpoint
	clientCleanup func()

	ctx       context.Context
	ctxCancel context.CancelCauseFunc
	closer    chan struct{}

	onlineReport func(err error)
}

func newClientEndpoint(ctx context.Context, cl *Client, ep endpoint, clientCleanup func()) (*clientEndpoint, error) {
	ctx, ctxCancel := context.WithCancelCause(ctx)
	cep := &clientEndpoint{
		client:        cl,
		ep:            ep,
		clientCleanup: clientCleanup,

		ctx:       ctx,
		ctxCancel: ctxCancel,
		closer:    make(chan struct{}),
	}
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

func (e *clientEndpoint) Addr() net.Addr {
	return e.client.directAddr
}

func (e *clientEndpoint) Client() *Client {
	return e.client
}

func (e *clientEndpoint) Close() error {
	e.ctxCancel(net.ErrClosed)
	<-e.closer
	return nil
}

func (e *clientEndpoint) runPeer(ctx context.Context) {
	if err := e.ep.RunPeer(ctx); err != nil {
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
		err := e.ep.RunAnnounce(ctx, sess.conn, sess.addrs, e.onlineReport)
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled):
			return
		case sess.conn.Context().Err() != nil:
			return
		default:
		}
	}
}

func (e *clientEndpoint) cleanup() {
	defer close(e.closer)
	e.clientCleanup()
}

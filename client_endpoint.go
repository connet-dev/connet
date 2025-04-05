package connet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/connet-dev/connet/client"
	"github.com/connet-dev/connet/model"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Destination interface {
	Accept() (net.Conn, error)
	AcceptContext(ctx context.Context) (net.Conn, error)

	Addr() net.Addr
	Client() *Client
	Close() error
}

type Source interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)

	Client() *Client
	Close() error
}

type clientDestination struct {
	*client.Destination
	*clientEndpoint
}

func newClientDestination(ctx context.Context, cl *Client, cfg client.DestinationConfig) (*clientDestination, error) {
	dst, err := client.NewDestination(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	ep, err := newClientEndpoint(ctx, cl, dst)
	if err != nil {
		return nil, err
	}

	return &clientDestination{dst, ep}, nil
}

type clientSource struct {
	*client.Source
	*clientEndpoint
}

func newClientSource(ctx context.Context, cl *Client, cfg client.SourceConfig) (*clientSource, error) {
	src, err := client.NewSource(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	ep, err := newClientEndpoint(ctx, cl, src)
	if err != nil {
		return nil, err
	}

	return &clientSource{src, ep}, nil
}

type clientEndpoint struct {
	client *Client
	cancel context.CancelCauseFunc
	closer chan struct{}
}

type endpoint interface {
	Forward() model.Forward
	Run(ctx context.Context) error
	RunControl(ctx context.Context, conn quic.Connection, directAddrs []netip.AddrPort, firstReport func(error)) error
}

func newClientEndpoint(ctx context.Context, cl *Client, ep endpoint) (*clientEndpoint, error) {
	closer := make(chan struct{})
	ctx, cancel := context.WithCancelCause(ctx)
	context.AfterFunc(ctx, func() {
		defer close(closer)

		cl.dstsMu.Lock()
		defer cl.dstsMu.Unlock()

		delete(cl.dsts, ep.Forward())
	})
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return ep.Run(ctx) })

	errCh := make(chan error)
	var reportOnce sync.Once
	var reportFn = func(err error) {
		reportOnce.Do(func() {
			if err != nil {
				errCh <- err
			}
			close(errCh)
		})
	}

	g.Go(func() error {
		return cl.sess.Listen(ctx, func(sess *session) error {
			if sess != nil {
				go func() {
					for {
						err := ep.RunControl(ctx, sess.conn, sess.addrs, reportFn)
						switch {
						case err == nil:
						case errors.Is(err, context.Canceled):
							return
						case sess.conn.Context().Err() != nil:
							return
						default:
						}
					}
				}()
			}
			return nil
		})
	})

	select {
	case <-ctx.Done():
		cancel(ctx.Err())
		return nil, ctx.Err()
	case err := <-errCh:
		if err != nil {
			cancel(err)
			return nil, err
		}
	}

	return &clientEndpoint{cl, cancel, closer}, nil
}

func (d *clientEndpoint) Addr() net.Addr {
	return d.client.directAddr
}

func (d *clientEndpoint) Client() *Client {
	return d.client
}

func (d *clientEndpoint) Close() error {
	d.cancel(net.ErrClosed)
	<-d.closer
	return nil
}

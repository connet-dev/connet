package connet

import (
	"context"
	"net"
	"sync"

	"github.com/connet-dev/connet/client"
	"golang.org/x/sync/errgroup"
)

type Destination interface {
	Accept() (net.Conn, error)
	AcceptContext(ctx context.Context) (net.Conn, error)

	Client() *Client

	Addr() net.Addr
	Close() error
}

type clientDestination struct {
	*client.Destination

	client *Client
	cancel context.CancelCauseFunc
	closer chan struct{}
}

func newClientDestination(ctx context.Context, cl *Client, cfg client.DestinationConfig) (*clientDestination, error) {
	dst, err := client.NewDestination(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	closer := make(chan struct{})
	ctx, cancel := context.WithCancelCause(ctx)
	context.AfterFunc(ctx, func() {
		defer close(closer)

		cl.dstsMu.Lock()
		defer cl.dstsMu.Unlock()

		delete(cl.dsts, cfg.Forward)
	})
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return dst.Run(ctx) })

	errCh := make(chan error)
	var reportOnce sync.Once

	g.Go(func() error {
		return cl.sess.Listen(ctx, func(sess *session) error {
			if sess != nil {
				go dst.RunControl(ctx, sess.conn, sess.addrs, func(err error) {
					reportOnce.Do(func() {
						if err != nil {
							errCh <- err
						}
						close(errCh)
					})
				})
			}
			return nil
		})
	})

	select {
	case <-ctx.Done():
		cancel(err)
		return nil, ctx.Err()
	case err := <-errCh:
		if err != nil {
			cancel(err)
			return nil, err
		}
	}

	return &clientDestination{dst, cl, cancel, closer}, nil
}

func (d *clientDestination) Client() *Client {
	return d.client
}

func (d *clientDestination) Addr() net.Addr {
	return d.client.directAddr
}

func (d *clientDestination) Close() error {
	d.cancel(net.ErrClosed)
	<-d.closer
	return nil
}

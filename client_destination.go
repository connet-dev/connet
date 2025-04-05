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

	Addr() net.Addr
	Close() error
}

type clientDestination struct {
	*client.Destination
	cancel context.CancelCauseFunc
}

func newClientDestination(ctx context.Context, cl *Client, cfg client.DestinationConfig) (*clientDestination, error) {
	dst, err := client.NewDestination(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancelCause(ctx)
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

	if err := <-errCh; err != nil { // TODO wait on context too?
		cancel(err)
		return nil, err
	}

	return &clientDestination{dst, cancel}, nil
}

func (d *clientDestination) Addr() net.Addr {
	// TODO how to implement
	return nil
}

func (d *clientDestination) Close() error {
	d.cancel(net.ErrClosed)
	return nil
}

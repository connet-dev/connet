package connet

import (
	"context"
	"net"
	"sync"

	"github.com/connet-dev/connet/client"
	"golang.org/x/sync/errgroup"
)

type Source interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)

	Close() error
}

type clientSource struct {
	*client.Source
	cancel context.CancelCauseFunc
}

func newClientSource(ctx context.Context, cl *Client, cfg client.SourceConfig) (*clientSource, error) {
	src, err := client.NewSource(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancelCause(ctx)
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return src.Run(ctx) })

	errCh := make(chan error)
	var reportOnce sync.Once

	g.Go(func() error {
		return cl.sess.Listen(ctx, func(sess *session) error {
			if sess != nil {
				go src.RunControl(ctx, sess.conn, sess.addrs, func(err error) {
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

	return &clientSource{src, cancel}, nil
}

func (s *clientSource) Close() error {
	s.cancel(net.ErrClosed)
	return nil
}

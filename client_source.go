package connet

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/connet-dev/connet/client"
	"golang.org/x/sync/errgroup"
)

type Source interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)

	Client() *Client
	Close() error
}

type clientSource struct {
	*client.Source

	client *Client
	cancel context.CancelCauseFunc
	closer chan struct{}
}

func newClientSource(ctx context.Context, cl *Client, cfg client.SourceConfig) (*clientSource, error) {
	src, err := client.NewSource(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	closer := make(chan struct{})
	ctx, cancel := context.WithCancelCause(ctx)
	context.AfterFunc(ctx, func() {
		defer close(closer)

		cl.srcsMu.Lock()
		defer cl.srcsMu.Unlock()

		delete(cl.srcs, cfg.Forward)
	})
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return src.Run(ctx) })

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
						err := src.RunControl(ctx, sess.conn, sess.addrs, reportFn)
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
		cancel(err)
		return nil, ctx.Err()
	case err := <-errCh:
		if err != nil {
			cancel(err)
			return nil, err
		}
	}

	return &clientSource{src, cl, cancel, closer}, nil
}

func (s *clientSource) Client() *Client {
	return s.client
}

func (s *clientSource) Close() error {
	s.cancel(net.ErrClosed)
	<-s.closer
	return nil
}

package connet

import (
	"context"
	"net"

	"github.com/connet-dev/connet/client"
)

type Source interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)

	Close() error
}

type clientSource struct {
	*client.Source
}

func newClientSource(ctx context.Context, cl *Client, cfg client.SourceConfig) (*clientSource, error) {
	src, err := client.NewSource(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	// TODO add to main run group, do we keep track?
	go func() {
		if err := src.Run(ctx); err != nil {
			// TODO what happens here
		}
	}()

	// TODO add to current run group
	errCh := make(chan error)
	go func() {
		var firstReport = func(err error) {
			if err != nil {
				errCh <- err
			}
			close(errCh)
		}
		err := cl.sess.Listen(ctx, func(sess *session) error {
			if sess != nil {
				go src.RunControl(ctx, sess.conn, sess.addrs, func(err error) {
					if firstReport != nil {
						firstReport(err)
						firstReport = nil
					}
				})
			}
			return nil
		})
		if err != nil {
			// TODO what happens here
		}
	}()

	if err := <-errCh; err != nil { // TODO wait on context too?
		return nil, err
	}

	return &clientSource{src}, nil
}

func (s *clientSource) Close() error {
	// TODO how to implement
	return nil
}

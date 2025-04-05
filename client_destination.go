package connet

import (
	"context"
	"net"

	"github.com/connet-dev/connet/client"
)

type Destination interface {
	Addr() net.Addr

	Accept() (net.Conn, error)
	AcceptContext(ctx context.Context) (net.Conn, error)

	Close() error
}

type clientDestination struct {
	*client.Destination
}

func newClientDestination(ctx context.Context, cl *Client, cfg client.DestinationConfig) (*clientDestination, error) {
	dst, err := client.NewDestination(cfg, cl.directServer, cl.rootCert, cl.logger)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := dst.Run(ctx); err != nil {
			// TODO what happens here
		}
	}()

	errCh := make(chan error)
	go func() {
		// TODO runcontrol should report error, the first time it comms with the server
		var firstReport = func(err error) {
			if err != nil {
				errCh <- err
			}
			close(errCh)
		}
		err := cl.sess.Listen(ctx, func(sess *session) error {
			if sess != nil {
				go dst.RunControl(ctx, sess.conn, sess.addrs, func(err error) {
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

	return &clientDestination{dst}, nil
}

func (d *clientDestination) Addr() net.Addr {
	// TODO how to implement
	return nil
}

func (d *clientDestination) Close() error {
	// TODO how to implement
	return nil
}

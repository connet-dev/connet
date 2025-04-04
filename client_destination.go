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

func (d *clientDestination) Addr() net.Addr {
	// TODO how to implement
	return nil
}

func (d *clientDestination) Close() error {
	// TODO how to implement
	return nil
}

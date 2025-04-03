package connet

import (
	"context"
	"net"
)

type Destination interface {
	Addr() net.Addr

	Accept() (net.Conn, error)
	AcceptContext(ctx context.Context) (net.Conn, error)

	Close() error
}

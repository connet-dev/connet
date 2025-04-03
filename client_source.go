package connet

import (
	"context"
	"net"
)

type Source interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

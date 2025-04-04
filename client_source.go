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

func (s *clientSource) Close() error {
	// TODO how to implement
	return nil
}

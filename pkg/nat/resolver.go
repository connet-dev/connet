package nat

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/connet-dev/connet/pkg/netc"
	"github.com/jackpal/gateway"
)

var errDiscoverInterface = errors.New("pmp discover interface")

func LocalIPSystemResolver() LocalIPResolver {
	return func(ctx context.Context) (net.IP, error) {
		localIP, err := gateway.DiscoverInterface()
		if err != nil {
			return net.IPv4zero, fmt.Errorf("%w: %w", errDiscoverInterface, err)
		}
		return localIP, nil
	}
}

func LocalIPDialResolver(addr string) LocalIPResolver {
	return func(ctx context.Context) (net.IP, error) {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			return net.IPv4zero, err
		}
		addr, err := netc.IPFromNet(conn.LocalAddr())
		if err != nil {
			return net.IPv4zero, err
		}
		return addr, nil
	}
}

var errDiscoverGateway = errors.New("pmp discover gateway")

func GatewayIPSystemResolver() GatewayIPResolver {
	return func(ctx context.Context, localIP net.IP) (net.IP, error) {
		gatewayIP, err := gateway.DiscoverGateway()
		if err != nil {
			return net.IPv4zero, fmt.Errorf("%w: %w", errDiscoverGateway, err)
		}
		return gatewayIP, nil
	}
}

func GatewayIPNet24Resolver() GatewayIPResolver {
	return func(ctx context.Context, localIP net.IP) (net.IP, error) {
		s := []byte(localIP)
		return net.IPv4(s[0], s[1], s[2], 1), nil
	}
}

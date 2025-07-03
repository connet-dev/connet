package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestPMP(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", ":19290")
	require.NoError(t, err)
	udpConn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer udpConn.Close()

	transport := &quic.Transport{Conn: udpConn}
	defer transport.Close()

	pm, err := NewPortmapper(transport, slog.Default())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go pm.Run(ctx)

	pm.externalAddrPort.Listen(ctx, func(t *netip.AddrPort) error {
		fmt.Println("received: ", t)
		return nil
	})
}

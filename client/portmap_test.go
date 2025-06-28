package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// func TestPCP(t *testing.T) {
// 	myIP, err := netip.ParseAddr(myIPAddr)
// 	require.NoError(t, err)
// 	data, err := pcpMapRequest(myIP)
// 	require.NoError(t, err)
// 	fmt.Printf("req: %x\n", data)

// 	addr, err := net.ResolveUDPAddr("udp", ":19190")
// 	require.NoError(t, err)
// 	udpConn, err := net.ListenUDP("udp", addr)
// 	require.NoError(t, err)
// 	defer udpConn.Close()

// 	transport := &quic.Transport{Conn: udpConn}
// 	defer transport.Close()

// 	gwIP := net.ParseIP(defaultGateway)
// 	n, err := transport.WriteTo(data, &net.UDPAddr{IP: gwIP, Port: defaultGatewayPort})
// 	require.NoError(t, err)
// 	require.EqualValues(t, len(data), n)

// 	var resp = make([]byte, 1100)
// 	m, resAddr, err := transport.ReadNonQUICPacket(context.Background(), resp)
// 	require.NoError(t, err)
// 	fmt.Printf("res from: %s\n", resAddr)
// 	fmt.Printf("res: %x\n", resp[0:m])
// }

func TestPMP(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", ":19190")
	require.NoError(t, err)
	udpConn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer udpConn.Close()

	transport := &quic.Transport{Conn: udpConn}
	defer transport.Close()

	pm, err := NewPortmapper(transport, slog.Default())
	require.NoError(t, err)

	dresult, err := pm.pmpDiscover(context.Background())
	require.NoError(t, err)

	fmt.Printf("Discover: epoch=%d, addr=%s\n", dresult.epochSeconds, dresult.externalAddr)

	mresult, err := pm.pmpMap(context.Background(), 19190, 0, 60)
	require.NoError(t, err)
	fmt.Printf("Map: epoch=%d, port=%d, lifetime=%d\n", mresult.epochSeconds, mresult.externalPort, mresult.lifetimeSeconds)
}

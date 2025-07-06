package nat

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalIPDial(t *testing.T) {
	addr, err := netip.ParseAddrPort("1.1.1.1:53")
	require.NoError(t, err)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: addr.Addr().AsSlice(), Port: int(addr.Port())})
	require.NoError(t, err)

	fmt.Println("local:", conn.LocalAddr())
}

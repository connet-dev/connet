package quicc

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

func ClientTransport(conn net.PacketConn, statelessResetKey *quic.StatelessResetKey) *quic.Transport {
	return &quic.Transport{
		Conn:              conn,
		StatelessResetKey: statelessResetKey,
		ConnContext:       RTTContext,
		// TODO review other options
	}
}

func ServerTransport(conn net.PacketConn, statelessResetKey *quic.StatelessResetKey) *quic.Transport {
	return &quic.Transport{
		Conn:               conn,
		ConnectionIDLength: 8,
		StatelessResetKey:  statelessResetKey,
		ConnContext:        RTTContext,
		// TODO review other options
	}
}

var StdConfig = &quic.Config{
	MaxIdleTimeout:  20 * time.Second,
	KeepAlivePeriod: 10 * time.Second,
	Tracer:          RTTTracer,
	// TODO review other options
}

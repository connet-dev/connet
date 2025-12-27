package quicc

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

func ClientTransport(conn net.PacketConn, statelessResetKey *quic.StatelessResetKey) *quic.Transport {
	return &quic.Transport{
		Conn:                             conn,
		StatelessResetKey:                statelessResetKey,
		DisableVersionNegotiationPackets: true,
		// TODO review other options
	}
}

func ServerTransport(conn net.PacketConn, statelessResetKey *quic.StatelessResetKey) *quic.Transport {
	return &quic.Transport{
		Conn:                             conn,
		ConnectionIDLength:               8,
		StatelessResetKey:                statelessResetKey,
		DisableVersionNegotiationPackets: true,
		// TODO review other options
	}
}

func ClientConfig(handshakeIdleTimeout time.Duration) *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: handshakeIdleTimeout,
		MaxIdleTimeout:       20 * time.Second,
		KeepAlivePeriod:      10 * time.Second,
		Versions:             []quic.Version{quic.Version1},
		// TODO review other options
	}
}

func ServerConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  20 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		Versions:        []quic.Version{quic.Version1},
		// TODO review other options
	}
}

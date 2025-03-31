package quicc

import (
	"net"

	"github.com/quic-go/quic-go"
)

func StreamConn(s quic.Stream, c quic.Connection) net.Conn {
	return &streamConn{
		Stream: s,
		Local:  c.LocalAddr(),
		Remote: c.RemoteAddr(),
	}
}

type streamConn struct {
	quic.Stream
	// TODO just use quic.Connection directly?
	Local  net.Addr
	Remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr {
	return s.Local
}

func (s *streamConn) RemoteAddr() net.Addr {
	return s.Remote
}

var _ net.Conn = (*streamConn)(nil)

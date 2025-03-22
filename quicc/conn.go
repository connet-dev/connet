package quicc

import (
	"net"

	"github.com/quic-go/quic-go"
)

type StreamConn struct {
	quic.Stream
	Local  net.Addr
	Remote net.Addr
}

func (s *StreamConn) LocalAddr() net.Addr {
	return s.Local
}

func (s *StreamConn) RemoteAddr() net.Addr {
	return s.Remote
}

var _ net.Conn = (*StreamConn)(nil)

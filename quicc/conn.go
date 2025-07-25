package quicc

import (
	"net"

	"github.com/quic-go/quic-go"
)

func StreamConn(s *quic.Stream, c *quic.Conn) net.Conn {
	return &streamConn{
		Stream: s,
		Local:  c.LocalAddr(),
		Remote: c.RemoteAddr(),
	}
}

type streamConn struct {
	*quic.Stream
	Local  net.Addr
	Remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr {
	return s.Local
}

func (s *streamConn) RemoteAddr() net.Addr {
	return s.Remote
}

func (s *streamConn) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}

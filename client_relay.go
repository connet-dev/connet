package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

type clientRelayServer struct {
	addr      netip.AddrPort
	name      string
	transport *quic.Transport
	cert      tls.Certificate
	relayCAs  *x509.CertPool
	dialer    *destinationsDialer
	logger    *slog.Logger
}

func (s *clientRelayServer) run(ctx context.Context) error {
	s.logger.Debug("dialing relay")
	conn, err := s.transport.Dial(ctx, net.UDPAddrFromAddrPort(s.addr), &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		RootCAs:      s.relayCAs,
		ServerName:   s.name,
		NextProtos:   []string{"connet-relay"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return nil
		}
		s.logger.Debug("accepted stream")
		go s.dialer.runRequest(ctx, stream)
	}
}

package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"time"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
)

type clientRelayServer struct {
	hostport  string
	transport *quic.Transport
	cert      tls.Certificate
	relayCAs  *x509.CertPool
	dialer    *destinationsDialer
	logger    *slog.Logger
}

func (s *clientRelayServer) run(ctx context.Context) error {
	s.logger.Debug("dialing relay")
	addr, err := net.ResolveUDPAddr("udp", s.hostport)
	if err != nil {
		return kleverr.Ret(err)
	}
	host, _, err := net.SplitHostPort(s.hostport)
	if err != nil {
		return kleverr.Ret(err)
	}
	conn, err := s.transport.Dial(ctx, addr, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		RootCAs:      s.relayCAs,
		ServerName:   host,
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

package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type clientDirectServer struct {
	dialer     *destinationsDialer
	transport  *quic.Transport
	serverCert tls.Certificate
	clientCA   atomic.Pointer[x509.CertPool]
	logger     *slog.Logger
}

func (s *clientDirectServer) run(ctx context.Context) error {
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{s.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"connet-direct"},
	}
	tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		conf := tlsConf.Clone()
		conf.ClientCAs = s.clientCA.Load()
		return conf, nil
	}

	l, err := s.transport.Listen(tlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return err
	}

	s.logger.Debug("listening for conns")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			return err
		}
		s.logger.Debug("accepted conn", "remote", conn.RemoteAddr())
		go s.runConn(ctx, conn)
	}
}

func (s *clientDirectServer) runConn(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "done")

	if err := s.runConnErr(ctx, conn); err != nil {
		s.logger.Warn("error handling conn", "err", err)
	}
}

func (s *clientDirectServer) runConnErr(ctx context.Context, conn quic.Connection) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		s.logger.Debug("serving direct conn", "remote", conn.RemoteAddr())
		go s.dialer.runRequest(ctx, stream)
	}
}

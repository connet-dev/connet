package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type DirectServer struct {
	transport *quic.Transport
	logger    *slog.Logger

	serverCers   []tls.Certificate
	serverCersMu sync.RWMutex

	clientCerts   map[string][]*x509.Certificate
	clientCertsMu sync.RWMutex

	activeConns   map[string]quic.Connection
	activeConnsMu sync.RWMutex
}

func NewDirectServer(transport *quic.Transport, logger *slog.Logger) *DirectServer {
	return &DirectServer{
		transport: transport,
		logger:    logger.With("component", "direct-server"),

		clientCerts: map[string][]*x509.Certificate{},

		activeConns: map[string]quic.Connection{},
	}
}

func (s *DirectServer) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runServer(ctx) })

	return g.Wait()
}

func (s *DirectServer) addServerCert(cert tls.Certificate) {
	s.serverCersMu.Lock()
	defer s.serverCersMu.Unlock()

	s.logger.Debug("server cert", "cert", printCert(cert.Leaf))
	s.serverCers = append(s.serverCers, cert)
}

func (s *DirectServer) getServerCerts() []tls.Certificate {
	s.serverCersMu.RLock()
	defer s.serverCersMu.RUnlock()

	return s.serverCers
}

func (s *DirectServer) setClientCerts(srv *x509.Certificate, certs []*x509.Certificate) {
	s.clientCertsMu.Lock()
	defer s.clientCertsMu.Unlock()

	for _, cert := range certs {
		s.logger.Debug("client cert", "cert", printCert(cert))
	}
	s.clientCerts[printCert(srv)] = certs
}

func (s *DirectServer) getClientCerts() *x509.CertPool {
	s.clientCertsMu.RLock()
	defer s.clientCertsMu.RUnlock()

	pool := x509.NewCertPool()
	for _, certs := range s.clientCerts {
		for _, cert := range certs {
			pool.AddCert(cert)
		}
	}
	return pool // TODO optimize this
}

func (s *DirectServer) runServer(ctx context.Context) error {
	tlsConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"connet-direct"},
	}
	tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		conf := tlsConf.Clone()
		conf.Certificates = s.getServerCerts()
		conf.ClientCAs = s.getClientCerts()
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
			if errors.Is(err, context.Canceled) {
				err = context.Cause(ctx)
			}
			s.logger.Warn("accept error", "err", err)
			return kleverr.Ret(err)
		}
		go s.runConn(ctx, conn)
	}
}

func (s *DirectServer) runConn(ctx context.Context, conn quic.Connection) {
	s.logger.Debug("accepted conn", "remote", conn.RemoteAddr())

	s.activeConnsMu.Lock()
	defer s.activeConnsMu.Unlock()

	clientCert := conn.ConnectionState().TLS.PeerCertificates[0]
	s.activeConns[printCert(clientCert)] = conn
}

func (s *DirectServer) getActiveConn(cert *x509.Certificate) (quic.Connection, bool) {
	s.activeConnsMu.RLock()
	defer s.activeConnsMu.RUnlock()

	conn, ok := s.activeConns[printCert(cert)]
	return conn, ok
}

func printCert(cert *x509.Certificate) string {
	v := sha256.Sum256(cert.Raw)
	return base64.RawStdEncoding.EncodeToString(v[:])
}

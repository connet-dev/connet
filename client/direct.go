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

	expectCerts   map[string]*expectedCert
	expectCertsMu sync.RWMutex
}

func NewDirectServer(transport *quic.Transport, logger *slog.Logger) *DirectServer {
	return &DirectServer{
		transport: transport,
		logger:    logger.With("component", "direct-server"),

		expectCerts: map[string]*expectedCert{},
	}
}

type expectedCert struct {
	cert *x509.Certificate
	ch   chan quic.Connection
}

func (s *DirectServer) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runServer(ctx) })

	return g.Wait()
}

func (s *DirectServer) addServerCert(cert tls.Certificate) {
	s.serverCersMu.Lock()
	defer s.serverCersMu.Unlock()

	s.logger.Debug("server cert", "cert", certKey(cert.Leaf))
	s.serverCers = append(s.serverCers, cert)
}

func (s *DirectServer) getServerCerts() []tls.Certificate {
	s.serverCersMu.RLock()
	defer s.serverCersMu.RUnlock()

	return s.serverCers
}

func (s *DirectServer) expectConn(cert *x509.Certificate) chan quic.Connection {
	ch := make(chan quic.Connection)

	s.expectCertsMu.Lock()
	defer s.expectCertsMu.Unlock()

	s.logger.Debug("client cert", "cert", certKey(cert))
	s.expectCerts[certKey(cert)] = &expectedCert{cert: cert, ch: ch}

	return ch
}

func (s *DirectServer) getClientCerts() *x509.CertPool {
	s.expectCertsMu.RLock()
	defer s.expectCertsMu.RUnlock()

	pool := x509.NewCertPool()
	for _, exp := range s.expectCerts {
		pool.AddCert(exp.cert)
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
		go s.runConn(conn)
	}
}

func (s *DirectServer) runConn(conn quic.Connection) {
	s.logger.Debug("accepted conn", "remote", conn.RemoteAddr())

	s.expectCertsMu.Lock()
	defer s.expectCertsMu.Unlock()

	key := certKey(conn.ConnectionState().TLS.PeerCertificates[0])
	exp := s.expectCerts[key]
	if exp == nil {
		conn.CloseWithError(1, "not found")
		return
	}
	exp.ch <- conn
	close(exp.ch)

	delete(s.expectCerts, key)
}

func certKey(cert *x509.Certificate) string {
	v := sha256.Sum256(cert.Raw)
	return base64.RawStdEncoding.EncodeToString(v[:])
}

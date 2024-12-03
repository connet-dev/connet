package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type DirectServer struct {
	transport *quic.Transport
	logger    *slog.Logger

	serverCers   []tls.Certificate
	serverCersMu sync.RWMutex

	expectCerts   map[certc.Key]*expectedCert
	expectCertsMu sync.RWMutex
}

func NewDirectServer(transport *quic.Transport, logger *slog.Logger) (*DirectServer, error) {
	return &DirectServer{
		transport: transport,
		logger:    logger.With("component", "direct-server"),

		expectCerts: map[certc.Key]*expectedCert{},
	}, nil
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

	s.logger.Debug("add server cert", "server", cert.Leaf.DNSNames[0], "cert", certc.NewKey(cert.Leaf))
	s.serverCers = append(s.serverCers, cert)
}

func (s *DirectServer) getServerCerts() []tls.Certificate {
	s.serverCersMu.RLock()
	defer s.serverCersMu.RUnlock()

	return s.serverCers
}

func (s *DirectServer) expectConn(cert *x509.Certificate) chan quic.Connection {
	key := certc.NewKey(cert)

	s.expectCertsMu.Lock()
	defer s.expectCertsMu.Unlock()

	if exp, ok := s.expectCerts[key]; ok {
		s.logger.Debug("cancel client", "cert", key)
		close(exp.ch)
	}

	s.logger.Debug("expect client", "cert", key)
	ch := make(chan quic.Connection)
	s.expectCerts[key] = &expectedCert{cert: cert, ch: ch}
	return ch
}

func (s *DirectServer) pollExpectedConn(cert *x509.Certificate) *expectedCert {
	key := certc.NewKey(cert)

	s.expectCertsMu.Lock()
	defer s.expectCertsMu.Unlock()

	if exp, ok := s.expectCerts[key]; ok {
		delete(s.expectCerts, key)
		return exp
	}
	return nil
}

func (s *DirectServer) getClientCerts() *x509.CertPool {
	s.expectCertsMu.RLock()
	defer s.expectCertsMu.RUnlock()

	s.logger.Debug("expect client certs", "certs", slices.Collect(maps.Keys(s.expectCerts)))
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
	key := certc.NewKey(conn.ConnectionState().TLS.PeerCertificates[0])
	s.logger.Debug("accepted conn", "cert", key, "remote", conn.RemoteAddr())

	if exp := s.pollExpectedConn(conn.ConnectionState().TLS.PeerCertificates[0]); exp != nil {
		// TODO do we ping/pong to verify?
		s.logger.Debug("accept client", "cert", key)
		exp.ch <- conn
		close(exp.ch)
	} else {
		conn.CloseWithError(1, "not found")
	}
}

package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/quic-go/quic-go"
)

type directServer struct {
	transport *quic.Transport
	logger    *slog.Logger

	servers   map[string]*vServer
	serversMu sync.RWMutex

	handshakeIdleTimeout time.Duration
}

func newDirectServer(transport *quic.Transport, handshakeIdleTimeout time.Duration, logger *slog.Logger) (*directServer, error) {
	return &directServer{
		transport: transport,
		logger:    logger.With("component", "direct-server"),

		servers: map[string]*vServer{},

		handshakeIdleTimeout: handshakeIdleTimeout,
	}, nil
}

type vServer struct {
	serverName string
	serverCert tls.Certificate
	clients    map[model.Key]*vClient
	clientCA   atomic.Pointer[x509.CertPool]
	mu         sync.RWMutex
}

type vClient struct {
	cert *x509.Certificate
	ch   chan *quic.Conn
}

func (s *vServer) dequeue(key model.Key, cert *x509.Certificate) *vClient {
	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.clients[key]; ok && exp.cert.Equal(cert) {
		delete(s.clients, key)
		return exp
	}

	return nil
}

func (s *vServer) updateClientCA() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clientCA := x509.NewCertPool()
	for _, exp := range s.clients {
		clientCA.AddCert(exp.cert)
	}
	s.clientCA.Store(clientCA)
}

func (s *directServer) addServerCert(cert tls.Certificate) {
	serverName := cert.Leaf.DNSNames[0]

	s.serversMu.Lock()
	defer s.serversMu.Unlock()

	s.logger.Debug("add server cert", "server", serverName, "cert", model.NewKey(cert.Leaf))
	s.servers[serverName] = &vServer{
		serverName: serverName,
		serverCert: cert,
		clients:    map[model.Key]*vClient{},
	}
}

func (s *directServer) getServer(serverName string) *vServer {
	s.serversMu.RLock()
	defer s.serversMu.RUnlock()

	return s.servers[serverName]
}

func (s *directServer) expect(serverCert tls.Certificate, cert *x509.Certificate) (chan *quic.Conn, func()) {
	key := model.NewKey(cert)
	srv := s.getServer(serverCert.Leaf.DNSNames[0])

	defer srv.updateClientCA()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	s.logger.Debug("expect client", "server", srv.serverName, "cert", key)
	cl := &vClient{cert: cert, ch: make(chan *quic.Conn)}
	srv.clients[key] = cl
	return cl.ch, func() {
		close(cl.ch)

		srv.mu.Lock()
		defer srv.mu.Unlock()

		if exp, ok := srv.clients[key]; ok && exp == cl {
			s.logger.Debug("unexpect client", "server", srv.serverName, "cert", key)
			delete(srv.clients, key)
		}
	}
}

func (s *directServer) Run(ctx context.Context) error {
	tlsConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: iterc.MapVarStrings(model.ConnectClientV01),
	}
	tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		srv := s.getServer(chi.ServerName)
		if srv == nil {
			return nil, fmt.Errorf("server not found: %s", chi.ServerName)
		}
		conf := tlsConf.Clone()
		conf.Certificates = []tls.Certificate{srv.serverCert}
		conf.ClientCAs = srv.clientCA.Load()
		return conf, nil
	}

	l, err := s.transport.Listen(tlsConf, quicc.ServerConfig())
	if err != nil {
		return err
	}
	defer func() {
		if err := l.Close(); err != nil {
			slogc.Fine(s.logger, "close listener error", "err", err)
		}
	}()

	s.logger.Debug("listening for conns")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			s.logger.Debug("accept error", "err", err)
			return fmt.Errorf("accept: %w", err)
		}
		go s.runConn(conn)
	}
}

func (s *directServer) runConn(conn *quic.Conn) {
	srv := s.getServer(conn.ConnectionState().TLS.ServerName)
	if srv == nil {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "unknown server"); err != nil {
			slogc.Fine(s.logger, "error closing connection", "err", err)
		}
		return
	}

	cert := conn.ConnectionState().TLS.PeerCertificates[0]
	key := model.NewKey(cert)
	s.logger.Debug("accepted conn", "server", srv.serverName, "cert", key, "remote", conn.RemoteAddr())

	exp := srv.dequeue(key, cert)
	if exp == nil {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "unknown client"); err != nil {
			slogc.Fine(s.logger, "error closing connection", "err", err)
		}
		return
	}

	s.logger.Debug("accept client", "server", srv.serverName, "cert", key)
	exp.ch <- conn
	close(exp.ch)

	srv.updateClientCA()
}

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type DirectServer struct {
	transport *quic.Transport
	logger    *slog.Logger

	servers   map[string]*vServer
	serversMu sync.RWMutex
}

func NewDirectServer(transport *quic.Transport, logger *slog.Logger) (*DirectServer, error) {
	return &DirectServer{
		transport: transport,
		logger:    logger.With("component", "direct-server"),

		servers: map[string]*vServer{},
	}, nil
}

type vServer struct {
	serverName string
	serverCert tls.Certificate
	clients    map[certc.Key]*vClient
	clientCA   atomic.Pointer[x509.CertPool]
	mu         sync.RWMutex
}

type vClient struct {
	cert *x509.Certificate
	ch   chan quic.Connection
}

func (s *vServer) dequeue(key certc.Key, cert *x509.Certificate) *vClient {
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

func (s *DirectServer) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runServer(ctx) })

	return g.Wait()
}

func (s *DirectServer) addServerCert(cert tls.Certificate) {
	serverName := cert.Leaf.DNSNames[0]

	s.serversMu.Lock()
	defer s.serversMu.Unlock()

	s.logger.Debug("add server cert", "server", serverName, "cert", certc.NewKey(cert.Leaf))
	s.servers[serverName] = &vServer{
		serverName: serverName,
		serverCert: cert,
		clients:    map[certc.Key]*vClient{},
	}
}

func (s *DirectServer) getServer(serverName string) *vServer {
	s.serversMu.RLock()
	defer s.serversMu.RUnlock()

	return s.servers[serverName]
}

func (s *DirectServer) expect(serverCert tls.Certificate, cert *x509.Certificate) (chan quic.Connection, func()) {
	key := certc.NewKey(cert)
	srv := s.getServer(serverCert.Leaf.DNSNames[0])

	defer srv.updateClientCA()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	s.logger.Debug("expect client", "server", srv.serverName, "cert", key)
	ch := make(chan quic.Connection)
	srv.clients[key] = &vClient{cert: cert, ch: ch}
	return ch, func() {
		srv.mu.Lock()
		defer srv.mu.Unlock()

		if exp, ok := srv.clients[key]; ok {
			s.logger.Debug("unexpect client", "server", srv.serverName, "cert", key)
			close(exp.ch)
			delete(srv.clients, key)
		}
	}
}

func (s *DirectServer) runServer(ctx context.Context) error {
	tlsConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"connet-direct"},
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

	l, err := s.transport.Listen(tlsConf, quicc.StdConfig)
	if err != nil {
		return err
	}

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

func (s *DirectServer) runConn(conn quic.Connection) {
	srv := s.getServer(conn.ConnectionState().TLS.ServerName)
	if srv == nil {
		conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "unknown server")
		return
	}

	cert := conn.ConnectionState().TLS.PeerCertificates[0]
	key := certc.NewKey(cert)
	s.logger.Debug("accepted conn", "server", srv.serverName, "cert", key, "remote", conn.RemoteAddr())

	exp := srv.dequeue(key, cert)
	if exp == nil {
		conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "unknown client")
		return
	}

	s.logger.Debug("accept client", "server", srv.serverName, "cert", key)
	exp.ch <- conn
	close(exp.ch)

	srv.updateClientCA()
}

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type DirectServer struct {
	transport *quic.Transport
	logger    *slog.Logger

	dsts   map[model.Forward]directClient
	srcs   map[model.Forward]directClient
	mu     sync.RWMutex
	notify *notify.N

	certs atomic.Pointer[directTLS]
}

func NewDirectServer(transport *quic.Transport, logger *slog.Logger) *DirectServer {
	return &DirectServer{
		transport: transport,
		logger:    logger.With("component", "direct-server"),

		notify: notify.New(),
	}
}

type directClient interface {
	ServerCert() tls.Certificate
	ClientCerts() []*x509.Certificate
}

type directTLS struct {
	certs []tls.Certificate
	cas   *x509.CertPool
}

func (s *DirectServer) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runClients(ctx) })
	g.Go(func() error { return s.runServer(ctx) })

	return g.Wait()
}

func (s *DirectServer) addDestination(fwd model.Forward, cl directClient) {
	defer s.notify.Updated()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.dsts[fwd] = cl
}

func (s *DirectServer) removeDestination(fwd model.Forward) {
	defer s.notify.Updated()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.dsts, fwd)
}

func (s *DirectServer) addSource(fwd model.Forward, cl directClient) {
	defer s.notify.Updated()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.srcs[fwd] = cl
}

func (s *DirectServer) removeSource(fwd model.Forward) {
	defer s.notify.Updated()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.srcs, fwd)
}

func (s *DirectServer) get() (map[model.Forward]directClient, map[model.Forward]directClient) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return maps.Clone(s.dsts), maps.Clone(s.srcs)
}

func (s *DirectServer) runClients(ctx context.Context) error {
	return s.notify.Listen(ctx, func() error {
		dsts, srcs := s.get()

		var certs []tls.Certificate
		var cas = x509.NewCertPool()

		for _, cl := range dsts {
			certs = append(certs, cl.ServerCert())
			for _, cert := range cl.ClientCerts() {
				cas.AddCert(cert)
			}
		}
		for _, cl := range srcs {
			certs = append(certs, cl.ServerCert())
			for _, cert := range cl.ClientCerts() {
				cas.AddCert(cert)
			}
		}

		s.certs.Store(&directTLS{certs, cas})
		return nil
	})
}

func (s *DirectServer) runServer(ctx context.Context) error {
	tlsConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"connet-direct"},
	}
	tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		conf := tlsConf.Clone()
		if certs := s.certs.Load(); certs != nil {
			conf.Certificates = certs.certs
			conf.ClientCAs = certs.cas
		}
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
		s.logger.Debug("accepted conn", "remote", conn.RemoteAddr())
		go s.runConn(ctx, conn)
	}
}

func (s *DirectServer) runConn(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "done")
}

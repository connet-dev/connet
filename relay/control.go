package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbs"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type controlClient struct {
	hostport model.HostPort

	controlAddr    *net.UDPAddr
	controlToken   string
	controlTlsConf *tls.Config

	serversRoot      *certc.Cert
	serversByForward *notify.V[map[model.Forward]*relayServer]
	serversByName    map[string]*relayServer

	logger *slog.Logger
}

func (s *controlClient) getByName(serverName string) *relayServer {
	var srv *relayServer
	s.serversByForward.Sync(func() {
		srv = s.serversByName[serverName]
	})
	return srv
}

func (s *controlClient) clientTLSConfig(chi *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error) {
	srv := s.getByName(chi.ServerName)
	if srv != nil {
		cfg := base.Clone()
		cfg.Certificates = srv.tls
		cfg.ClientCAs = srv.cas.Load()
		return cfg, nil
	}
	return base, nil
}

func (s *controlClient) authenticate(serverName string, certs []*x509.Certificate) *clientAuth {
	srv := s.getByName(serverName)
	if srv == nil {
		return nil
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()

	key := certc.NewKey(certs[0])
	if dst := srv.desinations[key]; dst != nil {
		return &clientAuth{srv.fwd, true, false}
	}
	if src := srv.sources[key]; src != nil {
		return &clientAuth{srv.fwd, false, true}
	}

	return nil
}

func (s *controlClient) run(ctx context.Context, transport *quic.Transport) error {
	conn, err := s.connect(ctx, transport)
	if err != nil {
		return err
	}

	for {
		if err := s.runConnection(ctx, conn); err != nil {
			s.logger.Error("session ended", "err", err)
			switch {
			case errors.Is(err, context.Canceled):
				return err
				// TODO other terminal errors
			}
		}

		if conn, err = s.reconnect(ctx, transport); err != nil {
			return err
		}
	}
}

func (s *controlClient) connect(ctx context.Context, transport *quic.Transport) (quic.Connection, error) {
	conn, err := transport.Dial(ctx, s.controlAddr, s.controlTlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer authStream.Close()

	if err := pb.Write(authStream, &pbs.RelayAuth{
		Token: s.controlToken,
		Addr:  s.hostport.PB(),
	}); err != nil {
		return nil, err
	}

	resp := &pbs.RelayAuthResp{}
	if err := pb.Read(authStream, resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, err
	}

	return conn, nil
}

func (c *controlClient) reconnect(ctx context.Context, transport *quic.Transport) (quic.Connection, error) {
	d := netc.MinBackoff
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		c.logger.Debug("backoff wait", "d", d)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}

		if sess, err := c.connect(ctx, transport); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return sess, nil
		}

		d = netc.NextBackoff(d)
		t.Reset(d)
	}
}

func (s *controlClient) runConnection(ctx context.Context, conn quic.Connection) error {
	defer conn.CloseWithError(0, "done")

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runForwards(ctx, conn) })
	g.Go(func() error { return s.runCerts(ctx, conn) })

	return g.Wait()
}

func (s *controlClient) runForwards(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return err
	}

	for {
		req := &pbs.RelayClients{}
		if err := pb.Read(stream, req); err != nil {
			return err
		}

		for _, change := range req.Changes {
			cert, err := x509.ParseCertificate(change.ClientCertificate)
			if err != nil {
				return err
			}

			switch {
			case change.Destination != nil:
				fwd := model.NewForwardFromPB(change.Destination)
				if change.Change == pbs.RelayChange_ChangeDel {
					s.removeDestination(fwd, cert)
				} else if err := s.addDestination(fwd, cert); err != nil {
					return err
				}
			case change.Source != nil:
				fwd := model.NewForwardFromPB(change.Source)
				if change.Change == pbs.RelayChange_ChangeDel {
					s.removeSource(fwd, cert)
				} else if err := s.addSource(fwd, cert); err != nil {
					return err
				}
			}
		}
	}
}

func (s *controlClient) runCerts(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	last := map[model.Forward]struct{}{}
	return s.serversByForward.Listen(ctx, func(t map[model.Forward]*relayServer) error {
		resp := &pbs.RelayServers{}

		for fwd, srv := range t {
			if _, ok := last[fwd]; !ok {
				resp.Changes = append(resp.Changes, &pbs.RelayServers_Change{
					Server:            fwd.PB(),
					ServerCertificate: srv.cert.Raw,
					Change:            pbs.RelayChange_ChangePut,
				})
				last[fwd] = struct{}{}
			}
		}

		for fwd := range last {
			if _, ok := t[fwd]; !ok {
				resp.Changes = append(resp.Changes, &pbs.RelayServers_Change{
					Server: fwd.PB(),
					Change: pbs.RelayChange_ChangeDel,
				})
				delete(last, fwd)
			}
		}

		return pb.Write(stream, resp)
	})
}

func (s *controlClient) createServer(fwd model.Forward) (*relayServer, error) {
	if srv := s.getServer(fwd); srv != nil {
		return srv, nil
	}

	serverRoot, err := s.serversRoot.NewServer(certc.CertOpts{
		Domains: []string{model.GenServerName("connet-relay")},
	})
	if err != nil {
		return nil, err
	}

	serverCert, err := serverRoot.TLSCert()
	if err != nil {
		return nil, err
	}

	srv := &relayServer{
		fwd:  fwd,
		cert: serverCert.Leaf,

		desinations: map[certc.Key]*x509.Certificate{},
		sources:     map[certc.Key]*x509.Certificate{},

		tls: []tls.Certificate{serverCert},
	}

	s.serversByForward.UpdateOpt(func(m map[model.Forward]*relayServer) (map[model.Forward]*relayServer, bool) {
		if m == nil {
			m = map[model.Forward]*relayServer{}
		} else {
			m = maps.Clone(m)
		}

		if added := m[fwd]; added != nil {
			srv = added
			return m, false
		}

		m[fwd] = srv
		s.serversByName[serverCert.Leaf.DNSNames[0]] = srv

		return m, true
	})

	return srv, nil
}

func (s *controlClient) addDestination(fwd model.Forward, cert *x509.Certificate) error {
	for {
		srv, err := s.createServer(fwd)
		if err != nil {
			return err
		}
		if srv.addDestination(cert) {
			return nil
		}
	}
}

func (s *controlClient) addSource(fwd model.Forward, cert *x509.Certificate) error {
	for {
		srv, err := s.createServer(fwd)
		if err != nil {
			return err
		}
		if srv.addSource(cert) {
			return nil
		}
	}
}

func (s *controlClient) getServer(fwd model.Forward) *relayServer {
	if srvs, err := s.serversByForward.Peek(); err != nil {
		return nil
	} else if srv, ok := srvs[fwd]; !ok {
		return nil
	} else {
		return srv
	}
}

func (s *controlClient) removeServer(srv *relayServer) {
	s.serversByForward.UpdateOpt(func(m map[model.Forward]*relayServer) (map[model.Forward]*relayServer, bool) {
		srv.mu.Lock()
		defer srv.mu.Unlock()

		if !srv.empty() {
			return m, false
		}

		srv.desinations = nil
		srv.sources = nil

		m = maps.Clone(m)
		delete(m, srv.fwd)
		return m, true
	})
}

func (s *controlClient) removeDestination(fwd model.Forward, cert *x509.Certificate) {
	srv := s.getServer(fwd)
	if srv == nil {
		return
	}
	if srv.removeDestination(cert) {
		s.removeServer(srv)
	}
}

func (s *controlClient) removeSource(fwd model.Forward, cert *x509.Certificate) {
	srv := s.getServer(fwd)
	if srv == nil {
		return
	}
	if srv.removeSource(cert) {
		s.removeServer(srv)
	}
}

type relayServer struct {
	fwd  model.Forward
	cert *x509.Certificate

	desinations map[certc.Key]*x509.Certificate
	sources     map[certc.Key]*x509.Certificate
	mu          sync.RWMutex

	tls []tls.Certificate
	cas atomic.Pointer[x509.CertPool]
}

func (s *relayServer) refreshCA() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cas := x509.NewCertPool()
	for _, cert := range s.desinations {
		cas.AddCert(cert)
	}
	for _, cert := range s.sources {
		cas.AddCert(cert)
	}
	s.cas.Store(cas)
}

func (s *relayServer) addDestination(cert *x509.Certificate) bool {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.desinations == nil {
		return false
	}

	s.desinations[certc.NewKey(cert)] = cert
	return true
}

func (s *relayServer) removeDestination(cert *x509.Certificate) bool {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.desinations, certc.NewKey(cert))

	return s.empty()
}

func (s *relayServer) addSource(cert *x509.Certificate) bool {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sources == nil {
		return false
	}

	s.sources[certc.NewKey(cert)] = cert
	return true
}

func (s *relayServer) removeSource(cert *x509.Certificate) bool {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sources, certc.NewKey(cert))

	return s.empty()
}

func (s *relayServer) empty() bool {
	return (len(s.desinations) + len(s.sources)) == 0
}

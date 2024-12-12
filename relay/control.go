package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
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

func (s *controlClient) createServer(fwd model.Forward) (*relayServer, error) {
	if srvs, err := s.serversByForward.Peek(); err != nil {
		// nothing in here, add it
	} else if srv, ok := srvs[fwd]; !ok {
		// not in here, add it
	} else {
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

	s.serversByForward.Update(func(m map[model.Forward]*relayServer) map[model.Forward]*relayServer {
		if m == nil {
			m = map[model.Forward]*relayServer{}
		} else {
			m = maps.Clone(m)
		}
		m[fwd] = srv

		s.serversByName[serverCert.Leaf.DNSNames[0]] = srv

		return m
	})
	return srv, nil
}

func (s *controlClient) getByName(serverName string) *relayServer {
	var srv *relayServer
	s.serversByForward.Sync(func() {
		srv = s.serversByName[serverName]
	})
	return srv
}

func (s *controlClient) run(ctx context.Context, tr *quic.Transport) error {
	// TODO reconnect loop
	conn, err := tr.Dial(ctx, s.controlAddr, s.controlTlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer authStream.Close()

	if err := pb.Write(authStream, &pbs.RelayAuth{
		Token: s.controlToken,
		Addr:  s.hostport.PB(),
	}); err != nil {
		return err
	}

	resp := &pbs.RelayAuthResp{}
	if err := pb.Read(authStream, resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return err
	}

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
				srv, err := s.createServer(fwd)
				if err != nil {
					return err
				}
				if change.Change == pbs.RelayChange_ChangeDel {
					srv.removeDestination(cert)
				} else {
					srv.addDestination(cert)
				}
			case change.Source != nil:
				fwd := model.NewForwardFromPB(change.Source)
				srv, err := s.createServer(fwd)
				if err != nil {
					return err
				}
				if change.Change == pbs.RelayChange_ChangeDel {
					srv.removeSource(cert)
				} else {
					srv.addSource(cert)
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

func (s *relayServer) addDestination(cert *x509.Certificate) {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.desinations[certc.NewKey(cert)] = cert
}

func (s *relayServer) removeDestination(cert *x509.Certificate) {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.desinations, certc.NewKey(cert))
}

func (s *relayServer) addSource(cert *x509.Certificate) {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sources[certc.NewKey(cert)] = cert
}

func (s *relayServer) removeSource(cert *x509.Certificate) {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sources, certc.NewKey(cert))
}

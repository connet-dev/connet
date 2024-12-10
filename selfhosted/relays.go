package selfhosted

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"sync/atomic"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/relay"
)

func NewLocalRelay(relayAddr model.HostPort) (*LocalRelay, error) {
	root, err := certc.NewRoot()
	if err != nil {
		return nil, err
	}
	return &LocalRelay{
		root:             root,
		relays:           notify.New(map[model.HostPort]struct{}{relayAddr: {}}),
		serversByName:    map[string]*relayServer{},
		serversByForward: map[model.Forward]*relayServer{},
	}, nil
}

type LocalRelay struct {
	root   *certc.Cert
	relays *notify.V[map[model.HostPort]struct{}]

	serversByName    map[string]*relayServer
	serversByForward map[model.Forward]*relayServer
	serversMu        sync.RWMutex
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

func (s *LocalRelay) createServer(fwd model.Forward) (*relayServer, error) {
	s.serversMu.RLock()
	srv := s.serversByForward[fwd]
	s.serversMu.RUnlock()

	if srv != nil {
		return srv, nil
	}

	s.serversMu.Lock()
	defer s.serversMu.Unlock()

	srv = s.serversByForward[fwd]
	if srv != nil {
		return srv, nil
	}

	serverRoot, err := s.root.NewServer(certc.CertOpts{
		Domains: []string{model.GenServerName("connet-relay")},
	})
	if err != nil {
		return nil, err
	}

	serverCert, err := serverRoot.TLSCert()
	if err != nil {
		return nil, err
	}

	srv = &relayServer{
		fwd:  fwd,
		cert: serverCert.Leaf,

		desinations: map[certc.Key]*x509.Certificate{},
		sources:     map[certc.Key]*x509.Certificate{},

		tls: []tls.Certificate{serverCert},
	}
	s.serversByName[serverCert.Leaf.DNSNames[0]] = srv
	s.serversByForward[fwd] = srv
	return srv, nil
}

func (s *LocalRelay) getServerByName(serverName string) *relayServer {
	s.serversMu.RLock()
	defer s.serversMu.RUnlock()

	return s.serversByName[serverName]
}

func (s *LocalRelay) getServerByForward(fwd model.Forward) *relayServer {
	s.serversMu.RLock()
	defer s.serversMu.RUnlock()

	return s.serversByForward[fwd]
}

func (s *LocalRelay) Destination(ctx context.Context, fwd model.Forward, cert *x509.Certificate, notify func(map[model.HostPort]*x509.Certificate) error) error {
	cert, err := s.addDestination(fwd, cert)
	if err != nil {
		return err
	}
	defer s.removeDestination(fwd, cert)

	return s.relays.Listen(ctx, func(local map[model.HostPort]struct{}) error {
		relays := map[model.HostPort]*x509.Certificate{}
		for hp := range local {
			relays[hp] = cert
		}
		return notify(relays)
	})
}

func (s *LocalRelay) addDestination(fwd model.Forward, cert *x509.Certificate) (*x509.Certificate, error) {
	srv, err := s.createServer(fwd)
	if err != nil {
		return nil, err
	}

	defer srv.refreshCA()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.desinations[certc.NewKey(cert)] = cert

	return srv.cert, nil
}

func (s *LocalRelay) removeDestination(fwd model.Forward, cert *x509.Certificate) {
	srv := s.getServerByForward(fwd)

	defer srv.refreshCA()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	delete(srv.desinations, certc.NewKey(cert))
}

func (s *LocalRelay) Source(ctx context.Context, fwd model.Forward, cert *x509.Certificate, notify func(map[model.HostPort]*x509.Certificate) error) error {
	cert, err := s.addSource(fwd, cert)
	if err != nil {
		return err
	}
	defer s.removeSource(fwd, cert)

	return s.relays.Listen(ctx, func(local map[model.HostPort]struct{}) error {
		relays := map[model.HostPort]*x509.Certificate{}
		for hp := range local {
			relays[hp] = cert
		}
		return notify(relays)
	})
}

func (s *LocalRelay) addSource(fwd model.Forward, cert *x509.Certificate) (*x509.Certificate, error) {
	srv, err := s.createServer(fwd)
	if err != nil {
		return nil, err
	}

	defer srv.refreshCA()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.sources[certc.NewKey(cert)] = cert

	return srv.cert, nil
}

func (s *LocalRelay) removeSource(fwd model.Forward, cert *x509.Certificate) {
	srv := s.getServerByForward(fwd)

	defer srv.refreshCA()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	delete(srv.sources, certc.NewKey(cert))
}

func (s *LocalRelay) TLSConfig(serverName string) ([]tls.Certificate, *x509.CertPool) {
	if srv := s.getServerByName(serverName); srv != nil {
		return srv.tls, srv.cas.Load()
	}
	return nil, nil
}

func (s *LocalRelay) Authenticate(serverName string, certs []*x509.Certificate) relay.Authentication {
	srv := s.getServerByName(serverName)
	if srv == nil {
		return nil
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()

	key := certc.NewKey(certs[0])
	if dst := srv.desinations[key]; dst != nil {
		return &localAuth{srv.fwd, true}
	}
	if src := srv.sources[key]; src != nil {
		return &localAuth{srv.fwd, false}
	}

	return nil
}

type localAuth struct {
	fwd model.Forward
	dst bool
}

func (l *localAuth) Forward() model.Forward {
	return l.fwd
}

func (l *localAuth) IsDestination() bool {
	return l.dst
}

func (l *localAuth) IsSource() bool {
	return !l.dst
}

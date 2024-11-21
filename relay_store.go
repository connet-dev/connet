package connet

import (
	"crypto/sha256"
	"crypto/x509"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

type RelayStoreManager interface {
	Add(cert *x509.Certificate, destinations []Binding, sources []Binding)
	Remove(cert *x509.Certificate)
	Relays() []string
}

type RelayStore interface {
	Authenticate(certs []*x509.Certificate) *RelayAuthentication
	CertificateAuthority() *x509.CertPool
}

type RelayAuthentication struct {
	Certificate  *x509.Certificate
	Destinations map[Binding]struct{}
	Sources      map[Binding]struct{}
}

func (a *RelayAuthentication) AllowDestination(bind Binding) bool {
	_, ok := a.Destinations[bind]
	return ok
}

func (a *RelayAuthentication) AllowSource(bind Binding) bool {
	_, ok := a.Sources[bind]
	return ok
}

type LocalRelayStore interface {
	RelayStoreManager
	RelayStore
}

func NewLocalRelayStore(addr netip.AddrPort, name string) (LocalRelayStore, error) {
	return &localRelayStore{
		relays: map[netip.AddrPort]string{addr: name},
		certs:  map[relayStoreKey]*RelayAuthentication{},
	}, nil
}

type localRelayStore struct {
	relays  map[netip.AddrPort]string
	certs   map[relayStoreKey]*RelayAuthentication
	certsMu sync.RWMutex
	pool    atomic.Pointer[x509.CertPool]
}

type relayStoreKey [sha256.Size]byte // TODO another key?

func (s *localRelayStore) Add(cert *x509.Certificate, destinations []Binding, sources []Binding) {
	s.certsMu.Lock()
	defer s.certsMu.Unlock()

	auth := &RelayAuthentication{
		Certificate:  cert,
		Destinations: map[Binding]struct{}{},
		Sources:      map[Binding]struct{}{},
	}
	for _, dst := range destinations {
		auth.Destinations[dst] = struct{}{}
	}
	for _, src := range sources {
		auth.Sources[src] = struct{}{}
	}

	s.certs[sha256.Sum256(cert.Raw)] = auth

	pool := x509.NewCertPool()
	for _, cfg := range s.certs {
		pool.AddCert(cfg.Certificate)
	}
	s.pool.Store(pool)
}

func (s *localRelayStore) Remove(cert *x509.Certificate) {
	s.certsMu.Lock()
	defer s.certsMu.Unlock()

	hash := sha256.Sum256(cert.Raw)
	delete(s.certs, hash)

	pool := x509.NewCertPool()
	for _, cfg := range s.certs {
		pool.AddCert(cfg.Certificate)
	}
	s.pool.Store(pool)
}

func (s *localRelayStore) Relays() []string {
	return slices.Collect(maps.Values(s.relays))
}

func (s *localRelayStore) Authenticate(certs []*x509.Certificate) *RelayAuthentication {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()

	for _, cert := range certs {
		if auth := s.certs[sha256.Sum256(cert.Raw)]; auth != nil {
			return auth
		}
	}

	return nil
}

func (s *localRelayStore) CertificateAuthority() *x509.CertPool {
	return s.pool.Load()
}

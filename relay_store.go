package connet

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
)

type RelayStoreManager interface {
	Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward)
	Remove(cert *x509.Certificate)
	Relays() []string
	RelaysNotify(ctx context.Context, f func(hostports []string) error) error
}

type RelayStore interface {
	Authenticate(certs []*x509.Certificate) *RelayAuthentication
	CertificateAuthority() *x509.CertPool
}

type RelayAuthentication struct {
	Certificate  *x509.Certificate
	Destinations map[model.Forward]struct{}
	Sources      map[model.Forward]struct{}
}

func (a *RelayAuthentication) AllowDestination(fwd model.Forward) bool {
	_, ok := a.Destinations[fwd]
	return ok
}

func (a *RelayAuthentication) AllowSource(fwd model.Forward) bool {
	_, ok := a.Sources[fwd]
	return ok
}

type LocalRelayStore interface {
	RelayStoreManager
	RelayStore
}

func NewLocalRelayStore(addr netip.AddrPort, name string) (LocalRelayStore, error) {
	s := &localRelayStore{
		relays:       map[netip.AddrPort]string{addr: name},
		relaysNotify: notify.New(),
		certs:        map[relayStoreKey]*RelayAuthentication{},
	}
	s.relaysNotify.Updated() // in local put notify at version 1, so new listens will return the static value and never fire again
	return s, nil
}

type localRelayStore struct {
	relays       map[netip.AddrPort]string
	relaysNotify *notify.N
	certs        map[relayStoreKey]*RelayAuthentication
	certsMu      sync.RWMutex
	pool         atomic.Pointer[x509.CertPool]
}

type relayStoreKey [sha256.Size]byte // TODO another key?

func (s *localRelayStore) Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward) {
	s.certsMu.Lock()
	defer s.certsMu.Unlock()

	auth := &RelayAuthentication{
		Certificate:  cert,
		Destinations: map[model.Forward]struct{}{},
		Sources:      map[model.Forward]struct{}{},
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

func (s *localRelayStore) RelaysNotify(ctx context.Context, f func([]string) error) error {
	return s.relaysNotify.Listen(ctx, func() error {
		return f(s.Relays())
	})
}

func (s *localRelayStore) Authenticate(certs []*x509.Certificate) *RelayAuthentication {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()

	for _, cert := range certs {
		if auth := s.certs[sha256.Sum256(cert.Raw)]; auth != nil && auth.Certificate.Equal(cert) {
			return auth
		}
	}

	return nil
}

func (s *localRelayStore) CertificateAuthority() *x509.CertPool {
	return s.pool.Load()
}

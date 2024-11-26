package relay

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

type StoreManager interface {
	Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward)
	Remove(cert *x509.Certificate)
	Relays() []string
	RelaysNotify(ctx context.Context, f func(hostports []string) error) error
}

type Store interface {
	Authenticate(certs []*x509.Certificate) *Authentication
	CertificateAuthority() *x509.CertPool
}

type Authentication struct { // interface like authc?
	Certificate  *x509.Certificate
	Destinations map[model.Forward]struct{}
	Sources      map[model.Forward]struct{}
}

func (a *Authentication) AllowDestination(fwd model.Forward) bool {
	_, ok := a.Destinations[fwd]
	return ok
}

func (a *Authentication) AllowSource(fwd model.Forward) bool {
	_, ok := a.Sources[fwd]
	return ok
}

type LocalStore interface {
	StoreManager
	Store
}

func NewLocalStore(addr netip.AddrPort, name string) (LocalStore, error) {
	s := &localStore{
		relays:       map[netip.AddrPort]string{addr: name},
		relaysNotify: notify.New(),
		certs:        map[storeKey]*Authentication{},
	}
	s.relaysNotify.Updated() // in local put notify at version 1, so new listens will return the static value and never fire again
	return s, nil
}

type localStore struct {
	relays       map[netip.AddrPort]string
	relaysNotify *notify.N
	certs        map[storeKey]*Authentication
	certsMu      sync.RWMutex
	pool         atomic.Pointer[x509.CertPool]
}

type storeKey [sha256.Size]byte // TODO another key?

func (s *localStore) Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward) {
	s.certsMu.Lock()
	defer s.certsMu.Unlock()

	auth := &Authentication{
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

func (s *localStore) Remove(cert *x509.Certificate) {
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

func (s *localStore) Relays() []string {
	return slices.Collect(maps.Values(s.relays))
}

func (s *localStore) RelaysNotify(ctx context.Context, f func([]string) error) error {
	return s.relaysNotify.Listen(ctx, func() error {
		return f(s.Relays())
	})
}

func (s *localStore) Authenticate(certs []*x509.Certificate) *Authentication {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()

	for _, cert := range certs {
		if auth := s.certs[sha256.Sum256(cert.Raw)]; auth != nil && auth.Certificate.Equal(cert) {
			return auth
		}
	}

	return nil
}

func (s *localStore) CertificateAuthority() *x509.CertPool {
	return s.pool.Load()
}

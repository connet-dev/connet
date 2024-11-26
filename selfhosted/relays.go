package selfhosted

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
	"github.com/keihaya-com/connet/relay"
)

func NewRelaySync(addr netip.AddrPort, hostport string) (*RelaySync, error) {
	s := &RelaySync{
		relays:       map[netip.AddrPort]string{addr: hostport},
		relaysNotify: notify.New(),
		certs:        map[storeKey]*relay.Authentication{},
	}
	s.relaysNotify.Updated() // in local put notify at version 1, so new listens will return the static value and never fire again
	return s, nil
}

type RelaySync struct {
	relays       map[netip.AddrPort]string
	relaysNotify *notify.N
	certs        map[storeKey]*relay.Authentication
	certsMu      sync.RWMutex
	pool         atomic.Pointer[x509.CertPool]
}

type storeKey [sha256.Size]byte // TODO another key?

func (s *RelaySync) Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward) {
	s.certsMu.Lock()
	defer s.certsMu.Unlock()

	auth := &relay.Authentication{
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

func (s *RelaySync) Remove(cert *x509.Certificate) {
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

func (s *RelaySync) Active() []string {
	return slices.Collect(maps.Values(s.relays))
}

func (s *RelaySync) ActiveNotify(ctx context.Context, f func([]string) error) error {
	return s.relaysNotify.Listen(ctx, func() error {
		return f(s.Active())
	})
}

func (s *RelaySync) Authenticate(certs []*x509.Certificate) *relay.Authentication {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()

	for _, cert := range certs {
		if auth := s.certs[sha256.Sum256(cert.Raw)]; auth != nil && auth.Certificate.Equal(cert) {
			return auth
		}
	}

	return nil
}

func (s *RelaySync) CertificateAuthority() *x509.CertPool {
	return s.pool.Load()
}

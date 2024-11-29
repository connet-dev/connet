package client

import (
	"context"
	"crypto/x509"
	"net/netip"
	"sync"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
)

type Source struct {
	fwd  model.Forward
	addr string
	opt  model.RouteOption
	cert *x509.Certificate

	peer       model.Peer
	peerMu     sync.RWMutex
	peerNotify *notify.N
}

func NewSource(fwd model.Forward, addr string, opt model.RouteOption, cert *x509.Certificate) (*Source, error) {
	return &Source{
		fwd:  fwd,
		addr: addr,
		opt:  opt,
		cert: cert,

		peerNotify: notify.New(),
	}, nil
}

func (s *Source) SetDirectAddrs(addrs []netip.AddrPort) {
	if !s.opt.AllowDirect() {
		return
	}

	routes := make([]model.Route, len(addrs))
	for i, addr := range addrs {
		routes[i] = model.Route{
			Hostport:    addr.String(),
			Certificate: s.cert,
		}
	}

	defer s.peerNotify.Updated()

	s.peerMu.Lock()
	defer s.peerMu.Unlock()

	s.peer.Directs = routes
}

func (s *Source) SetRelays(relays []model.Route) {
	if !s.opt.AllowRelay() {
		return
	}

	defer s.peerNotify.Updated()

	s.peerMu.Lock()
	defer s.peerMu.Unlock()

	s.peer.Relays = relays
}

func (s *Source) getPeer() model.Peer {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()

	return s.peer // TODO maybe copy
}

func (s *Source) Source(ctx context.Context, f func(peer model.Peer) error) error {
	return s.peerNotify.Listen(ctx, func() error {
		return f(s.getPeer())
	})
}

func (s *Source) Destinations(destinations []model.Peer) {

}

func (s *Source) Run(ctx context.Context) error {
	return nil
}

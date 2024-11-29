package client

import (
	"context"
	"crypto/x509"
	"net/netip"
	"sync"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
)

type Destination struct {
	fwd  model.Forward
	addr string
	opt  model.RouteOption
	cert *x509.Certificate

	peer       model.Peer
	peerMu     sync.RWMutex
	peerNotify *notify.N
}

func NewDestination(fwd model.Forward, addr string, opt model.RouteOption, cert *x509.Certificate) (*Destination, error) {
	return &Destination{
		fwd:  fwd,
		addr: addr,
		opt:  opt,
		cert: cert,

		peerNotify: notify.New(),
	}, nil
}

func (d *Destination) SetDirectAddrs(addrs []netip.AddrPort) {
	if !d.opt.AllowDirect() {
		return
	}

	routes := make([]model.Route, len(addrs))
	for i, addr := range addrs {
		routes[i] = model.Route{
			Hostport:    addr.String(),
			Certificate: d.cert,
		}
	}

	defer d.peerNotify.Updated()

	d.peerMu.Lock()
	defer d.peerMu.Unlock()

	d.peer.Directs = routes
}

func (d *Destination) SetRelays(relays []model.Route) {
	if !d.opt.AllowRelay() {
		return
	}

	defer d.peerNotify.Updated()

	d.peerMu.Lock()
	defer d.peerMu.Unlock()

	d.peer.Relays = relays
}

func (d *Destination) getPeer() model.Peer {
	d.peerMu.RLock()
	defer d.peerMu.RUnlock()

	return d.peer // TODO maybe copy
}

func (d *Destination) Destination(ctx context.Context, f func(peer model.Peer) error) error {
	return d.peerNotify.Listen(ctx, func() error {
		return f(d.getPeer())
	})
}

func (d *Destination) Sources(sources []model.Peer) {

}

func (d *Destination) Run(ctx context.Context) error {
	return nil
}

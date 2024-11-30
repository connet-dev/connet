package client

import (
	"context"
	"sync"

	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pbs"
)

type peer struct {
	self       *pbs.ClientPeer
	selfMu     sync.RWMutex
	selfNotify *notify.N

	peers       []*pbs.ServerPeer
	peersMu     sync.RWMutex
	peersNotify *notify.N
}

func newPeer() *peer {
	return &peer{
		self:        &pbs.ClientPeer{},
		selfNotify:  notify.New(),
		peersNotify: notify.New(),
	}
}

func (p *peer) setDirect(direct *pbs.DirectRoute) {
	defer p.selfNotify.Updated()

	p.selfMu.Lock()
	defer p.selfMu.Unlock()

	p.self.Direct = direct
}

func (p *peer) setRelays(relays []*pbs.RelayRoute) {
	defer p.selfNotify.Updated()

	p.selfMu.Lock()
	defer p.selfMu.Unlock()

	p.self.Relays = relays
}

func (p *peer) getSelf() *pbs.ClientPeer {
	p.selfMu.RLock()
	defer p.selfMu.RUnlock()

	return p.self
}

func (p *peer) selfListen(ctx context.Context, f func(self *pbs.ClientPeer) error) error {
	return p.selfNotify.Listen(ctx, func() error {
		return f(p.getSelf())
	})
}

func (p *peer) setPeers(peers []*pbs.ServerPeer) {
	defer p.peersNotify.Updated()

	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	p.peers = peers
}

func (p *peer) getPeers() []*pbs.ServerPeer {
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()

	return p.peers
}

func (p *peer) peersListen(ctx context.Context, f func(peers []*pbs.ServerPeer) error) error {
	return p.peersNotify.Listen(ctx, func() error {
		return f(p.getPeers())
	})
}

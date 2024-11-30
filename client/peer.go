package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pbs"
	"github.com/quic-go/quic-go"
)

type peer struct {
	self       *pbs.ClientPeer
	selfMu     sync.RWMutex
	selfNotify *notify.N

	peers       []*pbs.ServerPeer
	peersMu     sync.RWMutex
	peersNotify *notify.N

	active       map[netip.AddrPort]quic.Connection
	activeMu     sync.RWMutex
	activeNotify *notify.N

	transport  *quic.Transport
	clientCert tls.Certificate
	logger     *slog.Logger
}

func newPeer(transport *quic.Transport, clientCert tls.Certificate, logger *slog.Logger) *peer {
	return &peer{
		self:       &pbs.ClientPeer{},
		selfNotify: notify.New(),

		peersNotify: notify.New(),

		active:       map[netip.AddrPort]quic.Connection{},
		activeNotify: notify.New(),

		transport:  transport,
		clientCert: clientCert,
		logger:     logger,
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

func (p *peer) run(ctx context.Context) error {
	return p.peersListen(ctx, func(peers []*pbs.ServerPeer) error {
		p.logger.Debug("peers updated", "len", len(peers))
		for _, o := range peers {
			go p.runDirect(ctx, o)
			go p.runRelay(ctx, o)
		}
		return nil
	})
}

func (p *peer) addActive(ap netip.AddrPort, conn quic.Connection) {
	defer p.activeNotify.Updated()

	p.activeMu.Lock()
	defer p.activeMu.Unlock()

	p.active[ap] = conn
}

func (d *peer) getActive() map[netip.AddrPort]quic.Connection {
	d.activeMu.Lock()
	defer d.activeMu.Unlock()

	return maps.Clone(d.active)
}

func (p *peer) activeListen(ctx context.Context, f func(map[netip.AddrPort]quic.Connection) error) error {
	return p.activeNotify.Listen(ctx, func() error {
		return f(p.getActive())
	})
}

func (p *peer) runDirect(ctx context.Context, peer *pbs.ServerPeer) error {
	if peer.Direct == nil {
		return nil
	}
	for _, paddr := range peer.Direct.Addresses {
		p.logger.Debug("dialing direct", "addr", paddr.AsNetip())
		addr := net.UDPAddrFromAddrPort(paddr.AsNetip())

		directCert, err := x509.ParseCertificate(peer.Direct.ServerCertificate)
		if err != nil {
			return err
		}
		directCAs := x509.NewCertPool()
		directCAs.AddCert(directCert)

		conn, err := p.transport.Dial(ctx, addr, &tls.Config{
			Certificates: []tls.Certificate{p.clientCert},
			RootCAs:      directCAs,
			ServerName:   "connet-direct",
			NextProtos:   []string{"connet-direct"},
		}, &quic.Config{
			KeepAlivePeriod: 25 * time.Second,
		})
		if err != nil {
			p.logger.Debug("could not direct dial", "addr", addr, "err", err)
			continue
		}
		p.addActive(paddr.AsNetip(), conn)
		break
	}
	return nil
}

func (p *peer) runRelay(ctx context.Context, peer *pbs.ServerPeer) error {
	for _, r := range peer.Relays {
		p.logger.Debug("dialing relay", "addr", r.Address.AsNetip())
		addr := net.UDPAddrFromAddrPort(r.Address.AsNetip())

		relayCert, err := x509.ParseCertificate(r.ServerCertificate)
		if err != nil {
			return err
		}
		relayCAs := x509.NewCertPool()
		relayCAs.AddCert(relayCert)

		conn, err := p.transport.Dial(ctx, addr, &tls.Config{
			Certificates: []tls.Certificate{p.clientCert},
			RootCAs:      relayCAs,
			ServerName:   relayCert.DNSNames[0],
			NextProtos:   []string{"connet-relay"},
		}, &quic.Config{
			KeepAlivePeriod: 25 * time.Second,
		})
		if err != nil {
			p.logger.Debug("could not relay dial", "addr", r.Address.AsNetip(), "err", err)
			continue
		}
		p.addActive(r.Address.AsNetip(), conn)
	}
	return nil
}

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"time"

	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pbs"
	"github.com/quic-go/quic-go"
)

type peer struct {
	self   *notify.V[*pbs.ClientPeer]
	peers  *notify.V[[]*pbs.ServerPeer]
	active *notify.V[map[netip.AddrPort]quic.Connection]

	direct     *DirectServer
	clientCert tls.Certificate
	logger     *slog.Logger
}

func newPeer(direct *DirectServer, clientCert tls.Certificate, logger *slog.Logger) *peer {
	return &peer{
		self:  notify.NewV[*pbs.ClientPeer](nil),
		peers: notify.NewV[[]*pbs.ServerPeer](nil),
		active: notify.NewV(func(m map[netip.AddrPort]quic.Connection) map[netip.AddrPort]quic.Connection {
			return maps.Clone(m)
		}),

		direct:     direct,
		clientCert: clientCert,
		logger:     logger,
	}
}

func (p *peer) setDirect(direct *pbs.DirectRoute) {
	p.self.Update(func(cp *pbs.ClientPeer) *pbs.ClientPeer {
		if cp == nil {
			cp = &pbs.ClientPeer{}
		}
		cp.Direct = direct
		return cp
	})
}

func (p *peer) setRelays(relays []*pbs.RelayRoute) {
	p.self.Update(func(cp *pbs.ClientPeer) *pbs.ClientPeer {
		if cp == nil {
			cp = &pbs.ClientPeer{}
		}
		cp.Relays = relays
		return cp
	})
}

func (p *peer) selfListen(ctx context.Context, f func(self *pbs.ClientPeer) error) error {
	return p.self.Listen(ctx, f)
}

func (p *peer) setPeers(peers []*pbs.ServerPeer) {
	p.peers.Update(func(sp []*pbs.ServerPeer) []*pbs.ServerPeer {
		return peers
	})
}

func (p *peer) peersListen(ctx context.Context, f func(peers []*pbs.ServerPeer) error) error {
	return p.peers.Listen(ctx, f)
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
	p.active.Update(func(m map[netip.AddrPort]quic.Connection) map[netip.AddrPort]quic.Connection {
		if m == nil {
			m = map[netip.AddrPort]quic.Connection{}
		}
		m[ap] = conn
		return m
	})
}

func (d *peer) getActive() map[netip.AddrPort]quic.Connection {
	return d.active.Get()
}

func (p *peer) activeListen(ctx context.Context, f func(map[netip.AddrPort]quic.Connection) error) error {
	return p.active.Listen(ctx, f)
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

		conn, err := p.direct.transport.Dial(ctx, addr, &tls.Config{
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

		conn, err := p.direct.transport.Dial(ctx, addr, &tls.Config{
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

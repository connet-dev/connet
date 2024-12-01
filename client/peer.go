package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbs"
	"github.com/quic-go/quic-go"
)

type peer struct {
	self   *notify.V[*pbs.ClientPeer]
	peers  *notify.V[[]*pbs.ServerPeer]
	active *notify.V[map[peerConnKey]quic.Connection]

	direct     *DirectServer
	serverCert tls.Certificate
	clientCert tls.Certificate
	logger     *slog.Logger
}

type peerConnKey struct {
	id    string
	style string
}

func newPeer(direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*peer, error) {
	serverCert, err := root.NewServer(certc.CertOpts{Domains: []string{"connet-direct"}})
	if err != nil {
		return nil, err
	}
	serverTLSCert, err := serverCert.TLSCert()
	if err != nil {
		return nil, err
	}
	clientCert, err := root.NewClient(certc.CertOpts{})
	if err != nil {
		return nil, err
	}
	clientTLSCert, err := clientCert.TLSCert()
	if err != nil {
		return nil, err
	}

	return &peer{
		self:  notify.NewV(notify.InitialOpt(&pbs.ClientPeer{})),
		peers: notify.NewV[[]*pbs.ServerPeer](),
		active: notify.NewV(notify.InitialOpt(map[peerConnKey]quic.Connection{}),
			notify.CopyMapOpt[map[peerConnKey]quic.Connection]()),

		direct:     direct,
		serverCert: serverTLSCert,
		clientCert: clientTLSCert,
		logger:     logger,
	}, nil
}

func (p *peer) setDirectAddrs(addrs []netip.AddrPort) {
	p.self.Modify(func(cp *pbs.ClientPeer) {
		cp.Direct = &pbs.DirectRoute{
			Addresses:         pb.AsAddrPorts(addrs),
			ServerCertificate: p.serverCert.Leaf.Raw,
			ClientCertificate: p.clientCert.Leaf.Raw,
		}
	})
	p.direct.addServerCert(p.serverCert)
}

func (p *peer) setRelays(relays []*pbs.RelayRoute) {
	p.self.Modify(func(cp *pbs.ClientPeer) {
		cp.Relays = relays
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
		for _, sp := range peers {
			if sp.Direct != nil {
				go p.runDirectIncoming(ctx, sp)
				go p.runDirectOutgoing(ctx, sp)
			}
			go p.runRelay(ctx, sp)
		}
		return nil
	})
}

func (p *peer) addActive(id string, style string, conn quic.Connection) {
	p.active.Modify(func(m map[peerConnKey]quic.Connection) {
		m[peerConnKey{id, style}] = conn
	})
}

func (d *peer) getActive() map[peerConnKey]quic.Connection {
	return d.active.Get()
}

func (p *peer) activeListen(ctx context.Context, f func(map[peerConnKey]quic.Connection) error) error {
	return p.active.Listen(ctx, f)
}

func (p *peer) runDirectIncoming(ctx context.Context, peer *pbs.ServerPeer) error {
	cert, err := x509.ParseCertificate(peer.Direct.ClientCertificate)
	if err != nil {
		return err
	}
	ch := p.direct.expectConn(cert)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case conn := <-ch:
		p.logger.Debug("add direct incoming conn", "addr", peer.Direct.Addresses[0].AsNetip())
		p.addActive(peer.Id, "incoming", conn)
		return nil
	}
}

func (p *peer) runDirectOutgoing(ctx context.Context, peer *pbs.ServerPeer) error {
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
		p.logger.Debug("add direct outgoing conn", "addr", addr)
		p.addActive(peer.Id, "outgoing", conn)
		break
	}
	return nil
}

func (p *peer) runRelay(ctx context.Context, peer *pbs.ServerPeer) error {
	for _, r := range peer.Relays {
		hp := model.NewHostPortFromPB(r.Address)
		addr, err := net.ResolveUDPAddr("udp", hp.String())
		if err != nil {
			return err
		}

		p.logger.Debug("dialing relay", "hostport", hp, "addr", addr)

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
			p.logger.Debug("could not relay dial", "hostport", hp, "addr", addr, "err", err)
			continue
		}
		p.logger.Debug("add relay conn", "hostport", hp)
		p.addActive(peer.Id, "proxy", conn)
	}
	return nil
}

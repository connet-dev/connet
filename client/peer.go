package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"net/netip"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbs"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type peer struct {
	self       *notify.V[*pbs.ClientPeer]
	relays     *notify.V[[]*pbs.Relay]
	relayConns *notify.C[map[model.HostPort]quic.Connection]
	peers      *notify.V[[]*pbs.ServerPeer]
	peerConns  *notify.C[map[peerConnKey]quic.Connection]

	direct     *DirectServer
	serverCert tls.Certificate
	clientCert tls.Certificate
	logger     *slog.Logger
}

type peerConnKey struct {
	id    string
	style peerStyle
	key   string
}

type peerStyle int

const (
	peerOutgoing peerStyle = 0
	peerIncoming peerStyle = 1
	peerRelay    peerStyle = 2
)

func (s peerStyle) String() string {
	switch s {
	case peerOutgoing:
		return "outgoing"
	case peerIncoming:
		return "incoming"
	case peerRelay:
		return "relay"
	default:
		panic("invalid style")
	}
}

func newPeer(direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*peer, error) {
	serverCert, err := root.NewServer(certc.CertOpts{
		Domains: []string{model.GenServerName("connet-direct")},
	})
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
		self:       notify.New(&pbs.ClientPeer{}),
		relays:     notify.NewEmpty[[]*pbs.Relay](),
		relayConns: notify.New(map[model.HostPort]quic.Connection{}).Copying(maps.Clone),
		peers:      notify.NewEmpty[[]*pbs.ServerPeer](),
		peerConns:  notify.New(map[peerConnKey]quic.Connection{}).Copying(maps.Clone),

		direct:     direct,
		serverCert: serverTLSCert,
		clientCert: clientTLSCert,
		logger:     logger,
	}, nil
}

func (p *peer) expectDirect() {
	p.direct.addServerCert(p.serverCert)
}

func (p *peer) isDirect() bool {
	return p.direct.getServer(p.serverCert.Leaf.DNSNames[0]) != nil
}

func (p *peer) setDirectAddrs(addrs []netip.AddrPort) {
	p.self.Update(func(cp *pbs.ClientPeer) *pbs.ClientPeer {
		return &pbs.ClientPeer{
			Direct: &pbs.DirectRoute{
				Addresses:         pb.AsAddrPorts(addrs),
				ServerCertificate: p.serverCert.Leaf.Raw,
				ClientCertificate: p.clientCert.Leaf.Raw,
			},
			Relays: cp.Relays,
		}
	})
}

func (p *peer) setRelays(relays []*pbs.Relay) {
	p.relays.Set(relays)
}

func (p *peer) selfListen(ctx context.Context, f func(self *pbs.ClientPeer) error) error {
	return p.self.Listen(ctx, f)
}

func (p *peer) setPeers(peers []*pbs.ServerPeer) {
	p.peers.Set(peers)
}

func (p *peer) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return p.runRelays(ctx) })
	g.Go(func() error { return p.runShareRelays(ctx) })
	g.Go(func() error { return p.runPeers(ctx) })

	return g.Wait()
}

func (p *peer) runRelays(ctx context.Context) error {
	relayPeers := map[model.HostPort]*relayPeer{}
	return p.relays.Listen(ctx, func(relays []*pbs.Relay) error {
		p.logger.Debug("relays updated", "len", len(relays))

		activeRelays := map[model.HostPort]struct{}{}
		for _, relay := range relays {
			hp := model.HostPortFromPB(relay.Address)
			activeRelays[hp] = struct{}{}
			rlg := relayPeers[hp]

			cfg, err := newServerTLSConfig(relay.ServerCertificate)
			if err != nil {
				return err
			}
			if rlg != nil {
				rlg.serverConf.Store(cfg)
			} else {
				rlg = newRelayPeer(p, hp, cfg, p.logger)
				relayPeers[hp] = rlg
				go rlg.run(ctx)
			}
		}

		for hp, relay := range relayPeers {
			if _, ok := activeRelays[hp]; !ok {
				relay.stop()
				delete(relayPeers, hp)
			}
		}

		return nil
	})
}

func (p *peer) runShareRelays(ctx context.Context) error {
	return p.relayConns.Listen(ctx, func(conns map[model.HostPort]quic.Connection) error {
		p.logger.Debug("relays conns updated", "len", len(conns))
		var hps []*pb.HostPort
		for hp := range conns {
			hps = append(hps, hp.PB())
		}
		p.self.Update(func(cp *pbs.ClientPeer) *pbs.ClientPeer {
			return &pbs.ClientPeer{
				Direct: cp.Direct,
				Relays: hps,
			}
		})
		return nil
	})
}

func (p *peer) runPeers(ctx context.Context) error {
	peersByID := map[string]*directPeer{}
	return p.peers.Listen(ctx, func(peers []*pbs.ServerPeer) error {
		p.logger.Debug("peers updated", "len", len(peers))

		activeIDs := map[string]struct{}{}
		for _, sp := range peers {
			activeIDs[sp.Id] = struct{}{}
			prg := peersByID[sp.Id]
			if prg != nil {
				prg.remote.Set(sp)
			} else {
				prg = newPeering(p, sp, p.logger)
				peersByID[sp.Id] = prg
				go prg.run(ctx)
			}
		}

		for id, prg := range peersByID {
			if _, ok := activeIDs[id]; !ok {
				prg.stop()
				delete(peersByID, id)
			}
		}

		return nil
	})
}

func (p *peer) addRelayConn(hostport model.HostPort, conn quic.Connection) {
	p.relayConns.Update(func(conns map[model.HostPort]quic.Connection) {
		conns[hostport] = conn
	})
}

func (p *peer) removeRelayConn(hostport model.HostPort) {
	p.relayConns.Update(func(conns map[model.HostPort]quic.Connection) {
		delete(conns, hostport)
	})
}

func (p *peer) addActiveConn(id string, style peerStyle, key string, conn quic.Connection) {
	p.logger.Debug("add active connection", "peer", id, "style", style, "addr", conn.RemoteAddr())
	p.peerConns.Update(func(active map[peerConnKey]quic.Connection) {
		active[peerConnKey{id, style, key}] = conn
	})
}

func (p *peer) removeActiveConn(id string, style peerStyle, key string) {
	p.logger.Debug("remove active connection", "peer", id, "style", style)
	p.peerConns.Update(func(active map[peerConnKey]quic.Connection) {
		delete(active, peerConnKey{id, style, key})
	})
}

func (p *peer) removeActiveConns(id string) map[peerConnKey]quic.Connection {
	p.logger.Debug("remove active peer", "peer", id)
	removed := map[peerConnKey]quic.Connection{}
	p.peerConns.Update(func(active map[peerConnKey]quic.Connection) {
		for k, conn := range active {
			if k.id == id {
				removed[k] = conn
				delete(active, k)
			}
		}
	})
	return removed
}

func (p *peer) activeConnsListen(ctx context.Context, f func(map[peerConnKey]quic.Connection) error) error {
	return p.peerConns.Listen(ctx, f)
}

type serverTLSConfig struct {
	key  certc.Key
	name string
	cas  *x509.CertPool
}

func newServerTLSConfig(serverCert []byte) (*serverTLSConfig, error) {
	cert, err := x509.ParseCertificate(serverCert)
	if err != nil {
		return nil, err
	}
	cas := x509.NewCertPool()
	cas.AddCert(cert)
	return &serverTLSConfig{
		key:  certc.NewKey(cert),
		name: cert.DNSNames[0],
		cas:  cas,
	}, nil
}

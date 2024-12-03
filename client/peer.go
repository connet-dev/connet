package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbs"
	"github.com/mr-tron/base58"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type peer struct {
	self        *notify.V[*pbs.ClientPeer]
	peers       *notify.V[[]*pbs.ServerPeer]
	activePeers map[string]*peering
	activeConns *notify.V[map[peerConnKey]quic.Connection]

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
		panic("unknown style")
	}
}

func newPeer(direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*peer, error) {
	serverCert, err := root.NewServer(certc.CertOpts{Domains: []string{
		genServerName(),
	}})
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
		self:        notify.NewV(notify.InitialOpt(&pbs.ClientPeer{})),
		peers:       notify.NewV[[]*pbs.ServerPeer](),
		activePeers: map[string]*peering{},
		activeConns: notify.NewV(notify.InitialOpt(map[peerConnKey]quic.Connection{}),
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
		activeIds := map[string]struct{}{}
		for _, sp := range peers {
			activeIds[sp.Id] = struct{}{}
			prg := p.activePeers[sp.Id]
			if prg != nil {
				prg.remote.Set(sp)
			} else {
				prg = newPeering(p, sp, p.logger)
				p.activePeers[sp.Id] = prg
				go prg.run(ctx)
			}
		}

		for id, prg := range p.activePeers {
			if _, ok := activeIds[id]; !ok {
				prg.stop(ctx)
				delete(p.activePeers, id)
			}
		}
		return nil
	})
}

func (p *peer) addActiveConn(id string, style peerStyle, key string, conn quic.Connection) {
	p.logger.Debug("add active connection", "peer", id, "style", style, "addr", conn.RemoteAddr())
	p.activeConns.Modify(func(m map[peerConnKey]quic.Connection) {
		m[peerConnKey{id, style, key}] = conn
	})
}

func (p *peer) hasActiveConn(id string, style peerStyle, key string) bool {
	var ok bool
	p.activeConns.Inspect(func(m map[peerConnKey]quic.Connection) {
		_, ok = m[peerConnKey{id, style, key}]
	})
	return ok
}

func (p *peer) closeActiveConns(id string) {
	p.activeConns.Modify(func(m map[peerConnKey]quic.Connection) {
		for k, conn := range m {
			if k.id == id {
				conn.CloseWithError(0, "done")
				delete(m, k)
			}
		}
	})
}

func (p *peer) getActiveConns() map[peerConnKey]quic.Connection {
	return p.activeConns.Get()
}

func (p *peer) activeConnsListen(ctx context.Context, f func(map[peerConnKey]quic.Connection) error) error {
	return p.activeConns.Listen(ctx, f)
}

type peering struct {
	local *peer

	remoteId       string
	remote         *notify.V[*pbs.ServerPeer]
	directIncoming *notify.V[*x509.Certificate]
	directOutgoing *notify.V[*peeringOutoing]
	relays         *notify.V[map[model.HostPort]*x509.Certificate]

	closer chan struct{}

	logger *slog.Logger
}

type peeringOutoing struct {
	cert  *x509.Certificate
	addrs map[netip.AddrPort]struct{}
}

func newPeering(local *peer, remote *pbs.ServerPeer, logger *slog.Logger) *peering {
	p := &peering{
		local: local,

		remoteId:       remote.Id,
		remote:         notify.NewV[*pbs.ServerPeer](),
		directIncoming: notify.NewV[*x509.Certificate](),
		directOutgoing: notify.NewV[*peeringOutoing](),
		relays:         notify.NewV(notify.CopyMapOpt[map[model.HostPort]*x509.Certificate]()),

		closer: make(chan struct{}),

		logger: logger.With("peering", remote.Id),
	}
	p.remote.Set(remote)
	return p
}

var errPeeringStop = errors.New("peering stopped")

func (p *peering) run(ctx context.Context) {
	defer p.closeConns()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return p.runRemote(ctx) })
	g.Go(func() error { return p.runDirectIncoming(ctx) })
	g.Go(func() error { return p.runDirectOutgoing(ctx) })
	g.Go(func() error { return p.runRelay(ctx) })
	g.Go(func() error {
		<-p.closer
		return errPeeringStop
	})

	if err := g.Wait(); err != nil {
		p.logger.Warn("error while running peering", "err", err)
	}
}

func (p *peering) stop(ctx context.Context) {
	close(p.closer)
}

func (p *peering) closeConns() {
	p.local.closeActiveConns(p.remoteId)
}

func (p *peering) runRemote(ctx context.Context) error {
	return p.remote.Listen(ctx, func(remote *pbs.ServerPeer) error {
		if remote.Direct != nil {
			remoteClientCert, err := x509.ParseCertificate(remote.Direct.ClientCertificate)
			if err != nil {
				return err
			}
			p.directIncoming.Set(remoteClientCert)

			remoteServerCert, err := x509.ParseCertificate(remote.Direct.ServerCertificate)
			if err != nil {
				return err
			}
			addrs := map[netip.AddrPort]struct{}{}
			for _, addr := range remote.Direct.Addresses {
				addrs[addr.AsNetip()] = struct{}{}
			}
			p.directOutgoing.Set(&peeringOutoing{remoteServerCert, addrs})
		}

		relays := map[model.HostPort]*x509.Certificate{}
		for _, relay := range remote.Relays {
			cert, err := x509.ParseCertificate(relay.ServerCertificate)
			if err != nil {
				return err
			}
			relays[model.NewHostPortFromPB(relay.Address)] = cert
		}
		p.relays.Set(relays)

		return nil
	})
}

func (p *peering) runDirectIncoming(ctx context.Context) error {
	return p.directIncoming.Listen(ctx, func(cert *x509.Certificate) error {
		if p.local.hasActiveConn(p.remoteId, peerIncoming, "") {
			return nil
		}

		ch := p.local.direct.expectConn(cert)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case conn, ok := <-ch:
			if ok {
				p.local.addActiveConn(p.remoteId, peerIncoming, "", conn)
			}
			return nil
		}
	})
}

func (p *peering) runDirectOutgoing(ctx context.Context) error {
	return p.directOutgoing.Listen(ctx, func(out *peeringOutoing) error {
		if p.local.hasActiveConn(p.remoteId, peerOutgoing, "") {
			return nil
		}

		directCAs := x509.NewCertPool()
		directCAs.AddCert(out.cert)

		for paddr := range out.addrs {
			p.logger.Debug("attempt outgoing", "addr", paddr, "cert", certc.NewKey(p.local.clientCert.Leaf))
			addr := net.UDPAddrFromAddrPort(paddr)

			p.logger.Debug("dialing direct", "server", out.cert.DNSNames[0], "cert", certc.NewKey(out.cert))
			conn, err := p.local.direct.transport.Dial(ctx, addr, &tls.Config{
				Certificates: []tls.Certificate{p.local.clientCert},
				RootCAs:      directCAs,
				ServerName:   out.cert.DNSNames[0],
				NextProtos:   []string{"connet-direct"},
			}, &quic.Config{
				KeepAlivePeriod: 25 * time.Second,
			})
			if err != nil {
				p.logger.Debug("could not direct dial", "addr", addr, "err", err)
				continue
			}
			p.local.addActiveConn(p.remoteId, peerOutgoing, "", conn)
			break
		}
		return nil
	})
}

func (p *peering) runRelay(ctx context.Context) error {
	return p.relays.Listen(ctx, func(relays map[model.HostPort]*x509.Certificate) error {
		for hp, relayCert := range relays {
			if p.local.hasActiveConn(p.remoteId, peerRelay, hp.String()) {
				continue
			}

			addr, err := net.ResolveUDPAddr("udp", hp.String())
			if err != nil {
				return err
			}

			p.logger.Debug("attempt relay", "hostport", hp, "addr", addr)

			relayCAs := x509.NewCertPool()
			relayCAs.AddCert(relayCert)

			p.logger.Debug("dialing relay", "server", relayCert.DNSNames[0], "cert", certc.NewKey(relayCert))
			conn, err := p.local.direct.transport.Dial(ctx, addr, &tls.Config{
				Certificates: []tls.Certificate{p.local.clientCert},
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
			p.local.addActiveConn(p.remoteId, peerRelay, hp.String(), conn)
		}
		return nil
	})
}

func genServerName() string {
	v := binary.BigEndian.AppendUint64(nil, uint64(rand.Int64()))
	return fmt.Sprintf("connet-direct-%s", base58.Encode(v))
}

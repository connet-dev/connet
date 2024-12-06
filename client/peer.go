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
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/mr-tron/base58"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type peer struct {
	self             *notify.V[*pbs.ClientPeer]
	relays           *notify.V[[]*pbs.Relay]
	activeRelays     map[model.HostPort]*relaying
	activeRelayConns *notify.V[map[model.HostPort]quic.Connection]
	peers            *notify.V[[]*pbs.ServerPeer]
	activePeers      map[string]*peering
	activeConns      *notify.V[map[peerConnKey]quic.Connection]

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
		self:         notify.NewV(notify.InitialOpt(&pbs.ClientPeer{})),
		relays:       notify.NewV[[]*pbs.Relay](),
		activeRelays: map[model.HostPort]*relaying{},
		activeRelayConns: notify.NewV(notify.InitialOpt(map[model.HostPort]quic.Connection{}),
			notify.CopyMapOpt[map[model.HostPort]quic.Connection]()),
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

func (p *peer) expectDirect() {
	p.direct.addServerCert(p.serverCert)
}

func (p *peer) setDirectAddrs(addrs []netip.AddrPort) {
	p.self.Update(func(cp *pbs.ClientPeer) {
		cp.Direct = &pbs.DirectRoute{
			Addresses:         pb.AsAddrPorts(addrs),
			ServerCertificate: p.serverCert.Leaf.Raw,
			ClientCertificate: p.clientCert.Leaf.Raw,
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
	return p.relays.Listen(ctx, func(relays []*pbs.Relay) error {
		p.logger.Debug("relays updated", "len", len(relays))

		activeRelays := map[model.HostPort]struct{}{}
		for _, relay := range relays {
			hp := model.NewHostPortFromPB(relay.Address)
			activeRelays[hp] = struct{}{}
			rlg := p.activeRelays[hp]
			if rlg != nil {
				// TODO refresh cert?
			} else {
				cert, err := x509.ParseCertificate(relay.ServerCertificate)
				if err != nil {
					return err
				}

				rlg = newRelaying(p, hp, cert, p.logger)
				p.activeRelays[hp] = rlg
				go rlg.run(ctx)
			}
		}

		for hp, relay := range p.activeRelays {
			if _, ok := activeRelays[hp]; !ok {
				relay.stop()
				delete(p.activeRelays, hp)
			}
		}

		return nil
	})
}

func (p *peer) runShareRelays(ctx context.Context) error {
	return p.activeRelayConns.Listen(ctx, func(conns map[model.HostPort]quic.Connection) error {
		p.logger.Debug("relays conns updated", "len", len(conns))
		var hps []*pb.HostPort
		for hp := range conns {
			hps = append(hps, hp.PB())
		}
		p.self.Update(func(cp *pbs.ClientPeer) {
			cp.Relays = hps
		})
		return nil
	})
}

func (p *peer) runPeers(ctx context.Context) error {
	return p.peers.Listen(ctx, func(peers []*pbs.ServerPeer) error {
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
				prg.stop()
				delete(p.activePeers, id)
			}
		}

		return nil
	})
}

func (p *peer) addActiveConn(id string, style peerStyle, key string, conn quic.Connection) {
	p.logger.Debug("add active connection", "peer", id, "style", style, "addr", conn.RemoteAddr())
	p.activeConns.Update(func(active map[peerConnKey]quic.Connection) {
		active[peerConnKey{id, style, key}] = conn
	})
}

func (p *peer) hasActiveConn(id string, style peerStyle, key string) bool {
	var ok bool
	p.activeConns.Inspect(func(active map[peerConnKey]quic.Connection) {
		_, ok = active[peerConnKey{id, style, key}]
	})
	return ok
}

func (p *peer) removeActiveConns(id string) map[peerConnKey]quic.Connection {
	removed := map[peerConnKey]quic.Connection{}
	p.activeConns.Update(func(active map[peerConnKey]quic.Connection) {
		for k, conn := range active {
			if k.id == id {
				removed[k] = conn
				delete(active, k)
			}
		}
	})
	return removed
}

func (p *peer) getActiveConns() map[peerConnKey]quic.Connection {
	return p.activeConns.Get()
}

func (p *peer) activeConnsListen(ctx context.Context, f func(map[peerConnKey]quic.Connection) error) error {
	return p.activeConns.Listen(ctx, f)
}

type relaying struct {
	local *peer

	serverHostport model.HostPort
	serverCertKey  certc.Key
	serverName     string
	serverCA       *x509.CertPool
	// TODO optimize above fields to be passed once for all peers

	closer chan struct{}

	logger *slog.Logger
}

func newRelaying(local *peer, hp model.HostPort, cert *x509.Certificate, logger *slog.Logger) *relaying {
	cas := x509.NewCertPool()
	cas.AddCert(cert)
	return &relaying{
		local:          local,
		serverHostport: hp,
		serverCertKey:  certc.NewKey(cert),
		serverName:     cert.DNSNames[0],
		serverCA:       cas,
		closer:         make(chan struct{}),
		logger:         logger,
	}
}

func (r *relaying) run(ctx context.Context) {
	defer func() {
		r.local.activeRelayConns.Update(func(conns map[model.HostPort]quic.Connection) {
			delete(conns, r.serverHostport)
		})
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return r.runConn(ctx) })
	g.Go(func() error {
		<-r.closer
		return errPeeringStop
	})

	if err := g.Wait(); err != nil {
		r.logger.Warn("error while running relaying", "err", err)
	}
}

func (r *relaying) runConn(ctx context.Context) error {
	boff := netc.MinBackoff
	for {
		conn, err := r.connect(ctx)
		if err != nil {
			r.logger.Debug("could not connect relay", "relay", r.serverHostport, "err", err)
			if errors.Is(err, context.Canceled) {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(boff):
			}
			boff = netc.NextBackoff(boff)
			continue
		}

		boff = netc.MinBackoff
		if err := r.keepalive(ctx, conn); err != nil {
			r.logger.Debug("disconnected relay", "relay", r.serverHostport, "err", err)
		}
	}
}

func (r *relaying) connect(ctx context.Context) (quic.Connection, error) {
	addr, err := net.ResolveUDPAddr("udp", r.serverHostport.String())
	if err != nil {
		return nil, err
	}

	r.logger.Debug("dialing relay", "relay", r.serverHostport, "addr", addr, "server", r.serverName, "cert", r.serverCertKey)
	return r.local.direct.transport.Dial(ctx, addr, &tls.Config{
		Certificates: []tls.Certificate{r.local.clientCert},
		RootCAs:      r.serverCA,
		ServerName:   r.serverName,
		NextProtos:   []string{"connet-relay"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
}

func (r *relaying) keepalive(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if err := r.heartbeat(ctx, stream); err != nil {
		return err
	}

	r.local.activeRelayConns.Update(func(conns map[model.HostPort]quic.Connection) {
		conns[r.serverHostport] = conn
	})
	defer func() {
		r.local.activeRelayConns.Update(func(conns map[model.HostPort]quic.Connection) {
			delete(conns, r.serverHostport)
		})
	}()

	t := time.NewTicker(10 * time.Second) // TODO vary time
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		if err := r.heartbeat(ctx, stream); err != nil {
			return err
		}
	}
}

func (r *relaying) heartbeat(ctx context.Context, stream quic.Stream) error {
	// TODO setDeadline as additional assurance we are not blocked
	req := &pbc.Heartbeat{Time: timestamppb.Now()}
	if err := pb.Write(stream, &pbc.Request{Heartbeat: req}); err != nil {
		return err
	}
	if resp, err := pbc.ReadResponse(stream); err != nil {
		return err
	} else {
		dur := time.Since(resp.Heartbeat.Time.AsTime())
		r.logger.Debug("relay heartbeat", "relay", r.serverHostport, "dur", dur)
		return nil
	}
}

func (r *relaying) stop() {
	close(r.closer)
}

type peering struct {
	local *peer

	remoteId       string
	remote         *notify.V[*pbs.ServerPeer]
	directIncoming *notify.V[*x509.Certificate]
	directOutgoing *notify.V[*peeringOutoing]
	relays         *notify.V[map[model.HostPort]struct{}]

	closer chan struct{}

	logger *slog.Logger
}

type peeringOutoing struct {
	serverKey  certc.Key
	serverName string
	serverCA   *x509.CertPool
	addrs      map[netip.AddrPort]struct{}
}

func newPeering(local *peer, remote *pbs.ServerPeer, logger *slog.Logger) *peering {
	p := &peering{
		local: local,

		remoteId:       remote.Id,
		remote:         notify.NewV[*pbs.ServerPeer](),
		directIncoming: notify.NewV[*x509.Certificate](),
		directOutgoing: notify.NewV[*peeringOutoing](),
		relays:         notify.NewV(notify.CopyMapOpt[map[model.HostPort]struct{}]()),

		closer: make(chan struct{}),

		logger: logger.With("peering", remote.Id),
	}
	p.remote.Set(remote)
	return p
}

var errPeeringStop = errors.New("peering stopped")

func (p *peering) run(ctx context.Context) {
	defer func() {
		active := p.local.removeActiveConns(p.remoteId)
		for _, conn := range active {
			conn.CloseWithError(1, "depeered")
		}
	}()

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

func (p *peering) stop() {
	close(p.closer)
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
			remoteCA := x509.NewCertPool()
			remoteCA.AddCert(remoteServerCert)
			addrs := map[netip.AddrPort]struct{}{}
			for _, addr := range remote.Direct.Addresses {
				addrs[addr.AsNetip()] = struct{}{}
			}
			p.directOutgoing.Set(&peeringOutoing{
				certc.NewKey(remoteServerCert),
				remoteServerCert.DNSNames[0],
				remoteCA,
				addrs,
			})
		}

		relays := map[model.HostPort]struct{}{}
		for _, relay := range remote.Relays {
			relays[model.NewHostPortFromPB(relay)] = struct{}{}
		}
		p.relays.Set(relays)

		return nil
	})
}

func (p *peering) runDirectIncoming(ctx context.Context) error {
	return p.directIncoming.Listen(ctx, func(clientCert *x509.Certificate) error {
		if p.local.hasActiveConn(p.remoteId, peerIncoming, "") {
			return nil
		}

		ch := p.local.direct.expectConn(p.local.serverCert, clientCert)
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

		// TODO retry direct outgong conns to accomodate for network instability and NAT behavior
		for paddr := range out.addrs {
			addr := net.UDPAddrFromAddrPort(paddr)

			p.logger.Debug("dialing direct", "addr", addr, "server", out.serverName, "cert", out.serverKey)
			conn, err := p.local.direct.transport.Dial(ctx, addr, &tls.Config{
				Certificates: []tls.Certificate{p.local.clientCert},
				RootCAs:      out.serverCA,
				ServerName:   out.serverName,
				NextProtos:   []string{"connet-direct"},
			}, &quic.Config{
				KeepAlivePeriod: 25 * time.Second,
			})
			if err != nil {
				p.logger.Debug("could not dial direct", "addr", addr, "err", err)
				continue
			}
			p.local.addActiveConn(p.remoteId, peerOutgoing, "", conn)
			break
		}
		return nil
	})
}

func (p *peering) runRelay(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return p.local.activeRelayConns.Listen(ctx, func(relays map[model.HostPort]quic.Connection) error {
			p.logger.Debug("update local relays", "len", len(relays))
			peered := p.relays.Get()
			for hp := range peered {
				if p.local.hasActiveConn(p.remoteId, peerRelay, hp.String()) {
					continue
				}
				if conn := relays[hp]; conn != nil {
					p.local.addActiveConn(p.remoteId, peerRelay, hp.String(), conn)
				}
			}
			return nil
		})
	})

	g.Go(func() error {
		return p.relays.Listen(ctx, func(relays map[model.HostPort]struct{}) error {
			p.logger.Debug("update peer relays", "len", len(relays))
			active := p.local.activeRelayConns.Get()
			for hp := range relays {
				if p.local.hasActiveConn(p.remoteId, peerRelay, hp.String()) {
					continue
				}
				if conn := active[hp]; conn != nil {
					p.local.addActiveConn(p.remoteId, peerRelay, hp.String(), conn)
				}
			}
			return nil
		})
	})

	return g.Wait()
}

func genServerName() string {
	v := binary.BigEndian.AppendUint64(nil, uint64(rand.Int64()))
	return fmt.Sprintf("connet-direct-%s", base58.Encode(v))
}

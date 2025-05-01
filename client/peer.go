package client

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pbmodel"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type peer struct {
	self       *notify.V[*pbclient.ClientPeer]
	relays     *notify.V[[]*pbclient.Relay]
	relayConns *notify.V[map[relayID]relayConn]
	peers      *notify.V[[]*pbclient.ServerPeer]
	peerConns  *notify.V[map[peerConnKey]quic.Connection]

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

type relayConn struct { // TODO remove in 0.10.0
	conn quic.Connection
	hp   model.HostPort
}

func newPeer(direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*peer, error) {
	serverCert, err := root.NewServer(certc.CertOpts{
		Domains: []string{netc.GenServerName("connet-direct")},
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
		self: notify.New(&pbclient.ClientPeer{
			ServerCertificate: serverTLSCert.Leaf.Raw,
			ClientCertificate: clientTLSCert.Leaf.Raw,
		}),
		relays:     notify.NewEmpty[[]*pbclient.Relay](),
		relayConns: notify.New(map[relayID]relayConn{}),
		peers:      notify.NewEmpty[[]*pbclient.ServerPeer](),
		peerConns:  notify.New(map[peerConnKey]quic.Connection{}),

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
	p.self.Update(func(cp *pbclient.ClientPeer) *pbclient.ClientPeer {
		return &pbclient.ClientPeer{
			Direct: &pbclient.DirectRoute{
				Addresses:         pbmodel.AsAddrPorts(addrs),
				ServerCertificate: p.serverCert.Leaf.Raw,
				ClientCertificate: p.clientCert.Leaf.Raw,
			},
			Directs:           pbmodel.AsAddrPorts(addrs),
			Relays:            cp.Relays,
			RelayIds:          cp.RelayIds,
			ServerCertificate: cp.ServerCertificate,
			ClientCertificate: cp.ClientCertificate,
		}
	})
}

func (p *peer) setRelays(relays []*pbclient.Relay) {
	p.relays.Set(relays)
}

func (p *peer) selfListen(ctx context.Context, f func(self *pbclient.ClientPeer) error) error {
	return p.self.Listen(ctx, f)
}

func (p *peer) setPeers(peers []*pbclient.ServerPeer) {
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
	relayPeers := map[relayID]*relayPeer{}
	return p.relays.Listen(ctx, func(relays []*pbclient.Relay) error {
		p.logger.Debug("relays updated", "len", len(relays))

		activeRelays := map[relayID]struct{}{}
		for _, relay := range relays {
			id := relayID(relay.Id)
			hps := model.HostPortFromPBs(relay.Addresses)
			if id == "" {
				// TODO remove in 0.10.0: if id is missing, client is connected to an old server, use the hostport as id
				hp := model.HostPortFromPB(relay.Address)
				id = relayID(hp.String())
				hps = append(hps, hp)
			}

			activeRelays[id] = struct{}{}

			cfg, err := newServerTLSConfig(relay.ServerCertificate)
			if err != nil {
				return err
			}
			if rlg := relayPeers[id]; rlg != nil {
				rlg.serverConf.Store(cfg)
			} else {
				rlg = newRelayPeer(p, id, hps, cfg, p.logger)
				relayPeers[id] = rlg
				go rlg.run(ctx)
			}
		}

		for id, relay := range relayPeers {
			if _, ok := activeRelays[id]; !ok {
				relay.stop()
				delete(relayPeers, id)
			}
		}

		return nil
	})
}

func (p *peer) runShareRelays(ctx context.Context) error {
	return p.relayConns.Listen(ctx, func(conns map[relayID]relayConn) error {
		p.logger.Debug("relays conns updated", "len", len(conns))
		var ids []string
		var hps []*pbmodel.HostPort
		for id, conn := range conns {
			ids = append(ids, string(id))
			hps = append(hps, conn.hp.PB())
		}
		p.self.Update(func(cp *pbclient.ClientPeer) *pbclient.ClientPeer {
			return &pbclient.ClientPeer{
				Direct:            cp.Direct,
				Relays:            hps,
				Directs:           cp.Directs,
				RelayIds:          ids,
				ServerCertificate: cp.ServerCertificate,
				ClientCertificate: cp.ClientCertificate,
			}
		})
		return nil
	})
}

func (p *peer) runPeers(ctx context.Context) error {
	peersByID := map[string]*directPeer{}
	return p.peers.Listen(ctx, func(peers []*pbclient.ServerPeer) error {
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

func (p *peer) addRelayConn(id relayID, conn relayConn) {
	notify.MapPut(p.relayConns, id, conn)
}

func (p *peer) removeRelayConn(id relayID) {
	notify.MapDelete(p.relayConns, id)
}

func (p *peer) addActiveConn(id string, style peerStyle, key string, conn quic.Connection) {
	p.logger.Debug("add active connection", "peer", id, "style", style, "addr", conn.RemoteAddr())
	notify.MapPut(p.peerConns, peerConnKey{id, style, key}, conn)
}

func (p *peer) removeActiveConn(id string, style peerStyle, key string) {
	p.logger.Debug("remove active connection", "peer", id, "style", style)
	notify.MapDelete(p.peerConns, peerConnKey{id, style, key})
}

func (p *peer) removeActiveConns(id string) map[peerConnKey]quic.Connection {
	p.logger.Debug("remove active peer", "peer", id)
	removed := map[peerConnKey]quic.Connection{}
	notify.MapDeleteFunc(p.peerConns, func(k peerConnKey, conn quic.Connection) bool {
		if k.id == id {
			removed[k] = conn
			return true
		}
		return false
	})
	return removed
}

func (p *peer) activeConnsListen(ctx context.Context, f func(map[peerConnKey]quic.Connection) error) error {
	return p.peerConns.Listen(ctx, f)
}

type serverTLSConfig struct {
	key  model.Key
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
		key:  model.NewKey(cert),
		name: cert.DNSNames[0],
		cas:  cas,
	}, nil
}

func (p *peer) newECDHConfig() (*ecdh.PrivateKey, *pbconnect.ECDHConfiguration, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("peer generate key: %w", err)
	}

	var keyTime []byte
	keyTime = append(keyTime, sk.PublicKey().Bytes()...)
	keyTime = binary.BigEndian.AppendUint64(keyTime, uint64(time.Now().Nanosecond()))

	certSK := p.serverCert.PrivateKey.(ed25519.PrivateKey)
	signature, err := certSK.Sign(rand.Reader, keyTime, &ed25519.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("peer sign: %w", err)
	}

	return sk, &pbconnect.ECDHConfiguration{
		ClientName: p.serverCert.Leaf.DNSNames[0],
		KeyTime:    keyTime,
		Signature:  signature,
	}, nil
}

func (p *peer) getECDHPublicKey(cfg *pbconnect.ECDHConfiguration) (*ecdh.PublicKey, error) {
	peers, err := p.peers.Peek()
	if err != nil {
		return nil, fmt.Errorf("peers peer: %w", err)
	}
	var candidates []*x509.Certificate
	for _, peer := range peers {
		cert, err := x509.ParseCertificate(peer.ServerCertificate)
		if err != nil {
			return nil, err
		}
		if cert.DNSNames[0] == cfg.ClientName {
			candidates = append(candidates, cert)
		}
	}

	switch len(candidates) {
	case 0:
		return nil, fmt.Errorf("peer not found")
	case 1:
		// return candidates[0], nil
	default:
		return nil, fmt.Errorf("multiple peers found")
	}

	certPublic := candidates[0].PublicKey.(ed25519.PublicKey)
	if !ed25519.Verify(certPublic, cfg.KeyTime, cfg.Signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	keyBytes, timeBytes := cfg.KeyTime[0:len(cfg.KeyTime)-8], cfg.KeyTime[len(cfg.KeyTime)-8:]
	t := time.Unix(0, int64(binary.BigEndian.Uint64(timeBytes)))
	if time.Since(t) < 5*time.Minute {
		return nil, fmt.Errorf("time verification failed")
	}

	pk, err := ecdh.X25519().NewPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("new public key: %w", err)
	}
	return pk, nil
}

package connet

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
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pbmodel"
	"github.com/connet-dev/connet/reliable"
	"github.com/quic-go/quic-go"
)

type peer struct {
	self *notify.V[*pbclient.Peer]

	relays     *notify.V[[]*pbclient.Relay]
	relayConns *notify.V[map[relayID]*quic.Conn]

	directRelays     *notify.V[[]*pbclient.DirectRelay]
	directPeerRelays *notify.V[map[relayID]peerDirectRelay]

	peers     *notify.V[[]*pbclient.RemotePeer]
	peerConns *notify.V[map[peerConnKey]*quic.Conn]

	direct   *directServer
	addrs    *notify.V[advertiseAddrs]
	metadata string

	serverCert tls.Certificate
	clientCert tls.Certificate
	logger     *slog.Logger
}

type peerID string

type peerConnKey struct {
	id      peerID
	style   peerStyle
	relayID string
}

type peerStyle int

const (
	peerOutgoing      peerStyle = 0
	peerIncoming      peerStyle = 1
	peerRelay         peerStyle = 2
	peerRelayIncoming peerStyle = 3
	peerRelayOutgoing peerStyle = 4
)

func (s peerStyle) String() string {
	switch s {
	case peerOutgoing:
		return "outgoing"
	case peerIncoming:
		return "incoming"
	case peerRelay:
		return "relay"
	case peerRelayIncoming:
		return "relay-incoming"
	case peerRelayOutgoing:
		return "relay-outgoing"
	default:
		panic("invalid style")
	}
}

func (s peerStyle) isDirect() bool {
	switch s {
	case peerIncoming, peerOutgoing:
		return true
	default:
		return false
	}
}

func (s peerStyle) isRelay() bool {
	return !s.isDirect()
}

type peerDirectRelay struct {
	conn  *quic.Conn
	proto *pbclient.PeerDirectRelay
}

func newPeer(direct *directServer, addrs *notify.V[advertiseAddrs], metadata string, logger *slog.Logger) (*peer, error) {
	root, err := certc.NewRoot()
	if err != nil {
		return nil, err
	}

	serverCert, err := root.NewServer(certc.CertOpts{
		Domains: []string{netc.GenDomainName("connet.peer")},
	})
	if err != nil {
		return nil, err
	}
	serverTLSCert, err := serverCert.TLSCert()
	if err != nil {
		return nil, err
	}
	clientCert, err := root.NewClient()
	if err != nil {
		return nil, err
	}
	clientTLSCert, err := clientCert.TLSCert()
	if err != nil {
		return nil, err
	}

	direct.addServerCert(serverTLSCert)

	return &peer{
		self: notify.New(&pbclient.Peer{
			ServerCertificate: serverTLSCert.Leaf.Raw,
			ClientCertificate: clientTLSCert.Leaf.Raw,
		}),

		relays:     notify.NewEmpty[[]*pbclient.Relay](),
		relayConns: notify.NewEmpty[map[relayID]*quic.Conn](),

		directRelays:     notify.NewEmpty[[]*pbclient.DirectRelay](),
		directPeerRelays: notify.NewEmpty[map[relayID]peerDirectRelay](),

		peers:     notify.NewEmpty[[]*pbclient.RemotePeer](),
		peerConns: notify.NewEmpty[map[peerConnKey]*quic.Conn](),

		direct:   direct,
		addrs:    addrs,
		metadata: metadata,

		serverCert: serverTLSCert,
		clientCert: clientTLSCert,
		logger:     logger,
	}, nil
}

func (p *peer) setRelays(relays []*pbclient.Relay) {
	p.relays.Set(relays)
}

func (p *peer) setDirectRelays(relays []*pbclient.DirectRelay) {
	p.directRelays.Set(relays)
}

func (p *peer) selfListen(ctx context.Context, f func(self *pbclient.Peer) error) error {
	return p.self.Listen(ctx, f)
}

func (p *peer) setPeers(peers []*pbclient.RemotePeer) {
	p.peers.Set(peers)
}

func (p *peer) run(ctx context.Context) error {
	return reliable.RunGroup(ctx,
		p.runDirectAddrs,
		p.runRelays,
		p.runDirectRelays,
		p.runShareRelays,
		p.runShareDirectRelays,
		p.runPeers,
	)
}

func (p *peer) runDirectAddrs(ctx context.Context) error {
	return p.addrs.Listen(ctx, func(t advertiseAddrs) error {
		p.self.Update(func(cp *pbclient.Peer) *pbclient.Peer {
			return &pbclient.Peer{
				Directs:           pbmodel.AsAddrPorts(t.all()),
				RelayIds:          cp.RelayIds,
				ServerCertificate: cp.ServerCertificate,
				ClientCertificate: cp.ClientCertificate,
				Relays:            cp.Relays,
			}
		})
		return nil
	})
}

func (p *peer) runRelays(ctx context.Context) error {
	runningRelays := map[relayID]*relay{}
	return p.relays.Listen(ctx, func(relays []*pbclient.Relay) error {
		p.logger.Debug("relays updated", "len", len(relays))

		activeRelays := map[relayID]struct{}{}
		for _, relay := range relays {
			id := relayID(relay.Id)
			hps := model.HostPortFromPBs(relay.Addresses)

			activeRelays[id] = struct{}{}

			cfg, err := newServerTLSConfig(relay.ServerCertificate)
			if err != nil {
				return err
			}
			if rlg := runningRelays[id]; rlg != nil {
				p.logger.Debug("updating relay", "id", id)
				rlg.serverConf.Store(cfg)
			} else {
				p.logger.Debug("starting relay", "id", id)
				runningRelays[id] = runRelay(ctx, p, id, hps, cfg, p.logger)
			}
		}

		for id, relay := range runningRelays {
			if _, ok := activeRelays[id]; !ok {
				p.logger.Debug("stopping relay", "id", id)
				relay.cancel(errRelayRemoved)
				delete(runningRelays, id)
			}
		}

		return nil
	})
}

func (p *peer) runDirectRelays(ctx context.Context) error {
	runningRelays := map[relayID]*directRelay{}
	return p.directRelays.Listen(ctx, func(relays []*pbclient.DirectRelay) error {
		p.logger.Debug("direct relays updated", "len", len(relays))
		activeRelays := map[relayID]struct{}{}
		for _, relay := range relays {
			id := relayID(relay.Id)
			hps := model.HostPortFromPBs(relay.Addresses)

			activeRelays[id] = struct{}{}

			cfg, err := newServerTLSConfig(relay.ReserveCertificate)
			if err != nil {
				return fmt.Errorf("parse direct relay cert %s: %w", id, err)
			}
			if rlg := runningRelays[id]; rlg != nil {
				p.logger.Debug("updating direct relay", "id", id)
				rlg.serverConf.Store(cfg)
			} else {
				p.logger.Debug("starting direct relay", "id", id)
				runningRelays[id] = runDirectRelay(ctx, p, id, hps, cfg, p.logger)
			}
		}

		for id, relay := range runningRelays {
			if _, ok := activeRelays[id]; !ok {
				p.logger.Debug("stopping direct relay", "id", id)
				relay.cancel()
				delete(runningRelays, id)
			}
		}

		return nil
	})
}

func (p *peer) runShareRelays(ctx context.Context) error {
	return p.relayConns.Listen(ctx, func(conns map[relayID]*quic.Conn) error {
		p.logger.Debug("relays conns updated", "len", len(conns))
		var ids []string
		for id := range conns {
			ids = append(ids, string(id))
		}
		p.self.Update(func(cp *pbclient.Peer) *pbclient.Peer {
			return &pbclient.Peer{
				Directs:           cp.Directs,
				RelayIds:          ids,
				ServerCertificate: cp.ServerCertificate,
				ClientCertificate: cp.ClientCertificate,
				Relays:            cp.Relays,
			}
		})
		return nil
	})
}

func (p *peer) runShareDirectRelays(ctx context.Context) error {
	return p.directPeerRelays.Listen(ctx, func(relays map[relayID]peerDirectRelay) error {
		p.logger.Debug("direct peer relays updated", "len", len(relays))

		p.self.Update(func(cp *pbclient.Peer) *pbclient.Peer {
			return &pbclient.Peer{
				Directs:           cp.Directs,
				RelayIds:          cp.RelayIds,
				ServerCertificate: cp.ServerCertificate,
				ClientCertificate: cp.ClientCertificate,
				Relays: slices.Collect(iterc.Map(maps.Values(relays), func(r peerDirectRelay) *pbclient.PeerDirectRelay {
					return r.proto
				})),
			}
		})

		return nil
	})
}

func (p *peer) runPeers(ctx context.Context) error {
	runningPeers := map[string]*remotePeer{}
	return p.peers.Listen(ctx, func(peers []*pbclient.RemotePeer) error {
		p.logger.Debug("peers updated", "len", len(peers))

		activePeers := map[string]struct{}{}
		var toAdd []*pbclient.RemotePeer
		for _, sp := range peers {
			activePeers[sp.Id] = struct{}{}
			if prg := runningPeers[sp.Id]; prg != nil {
				p.logger.Debug("updating remote peer", "id", sp.Id)
				prg.remote.Set(sp)
			} else {
				toAdd = append(toAdd, sp)
			}
		}

		for id, prg := range runningPeers {
			if _, ok := activePeers[id]; !ok {
				p.logger.Debug("stopping remote peer", "id", id)
				prg.cancel(errRemotePeerRemoved)
				delete(runningPeers, id)
			}
		}

		for _, sp := range toAdd {
			p.logger.Debug("starting remote peer", "id", sp.Id)
			runningPeers[sp.Id] = runRemotePeer(ctx, p, sp, p.logger)
		}

		return nil
	})
}

func (p *peer) addRelayConn(id relayID, conn *quic.Conn) {
	notify.MapPut(p.relayConns, id, conn)
}

func (p *peer) removeRelayConn(id relayID) {
	notify.MapDelete(p.relayConns, id)
}

func (p *peer) addDirectPeerRelay(relay *pbclient.PeerDirectRelay, conn *quic.Conn) {
	notify.MapPut(p.directPeerRelays, relayID(relay.Id), peerDirectRelay{conn, relay})
}

func (p *peer) removeDirectPeerRelay(id relayID) {
	notify.MapDelete(p.directPeerRelays, id)
}

func (p *peer) addActiveConn(id peerID, style peerStyle, relayID string, conn *quic.Conn) {
	p.logger.Debug("add active connection", "peer", id, "style", style, "addr", conn.RemoteAddr(), "relay", relayID)
	notify.MapPut(p.peerConns, peerConnKey{id, style, relayID}, conn)
}

func (p *peer) removeActiveConn(id peerID, style peerStyle, relayID string) {
	p.logger.Debug("remove active connection", "peer", id, "style", style, "relay", relayID)
	notify.MapDelete(p.peerConns, peerConnKey{id, style, relayID})
}

func (p *peer) removeActiveConns(id peerID) map[peerConnKey]*quic.Conn {
	p.logger.Debug("remove active peer", "peer", id)
	removed := map[peerConnKey]*quic.Conn{}
	notify.MapDeleteFunc(p.peerConns, func(k peerConnKey, conn *quic.Conn) bool {
		if k.id == id {
			removed[k] = conn
			return true
		}
		return false
	})
	return removed
}

func (p *peer) activeConnsListen(ctx context.Context, f func(map[peerConnKey]*quic.Conn) error) error {
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
	remotes, ok := p.peers.Peek()
	if !ok {
		return nil, fmt.Errorf("no peers found")
	}
	var candidates []*x509.Certificate
	for _, remote := range remotes {
		cert, err := x509.ParseCertificate(remote.Peer.ServerCertificate)
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

type StatusPeer struct {
	// Relays show the status of each relay this peer is connected to
	Relays map[string]StatusRelayConnection `json:"relays"`
	// Directs shows the status of each direct relay this peer is connected to
	Directs map[string]StatusRelayConnection `json:"directs"`
	// Peers shows the status of each peer this peer is connected to
	Peers map[string]StatusRemotePeer `json:"peers"`
}

type StatusRelayConnection struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

type StatusRemotePeer struct {
	ID          string                       `json:"id"`
	Metadata    string                       `json:"metadata"`
	Connections []StatusRemotePeerConnection `json:"connections"`
}

type StatusRemotePeerConnection struct {
	Style   string `json:"style"`
	Address string `json:"address"`
	RelayID string `json:"relay-id,omitempty"`
}

func (p *peer) status() (StatusPeer, error) {
	stat := StatusPeer{
		Relays:  map[string]StatusRelayConnection{},
		Directs: map[string]StatusRelayConnection{},
		Peers:   map[string]StatusRemotePeer{},
	}

	if relays, ok := p.relayConns.Peek(); ok {
		for id, conn := range relays {
			stat.Relays[string(id)] = StatusRelayConnection{
				ID:      string(id),
				Address: conn.RemoteAddr().String(),
			}
		}
	}

	if relays, ok := p.directPeerRelays.Peek(); ok {
		for id, relay := range relays {
			stat.Directs[string(id)] = StatusRelayConnection{
				ID:      string(id),
				Address: relay.conn.RemoteAddr().String(),
			}
		}
	}

	if peers, ok := p.peers.Peek(); ok {
		for _, peer := range peers {
			stat.Peers[peer.Id] = StatusRemotePeer{ID: peer.Id, Metadata: peer.Metadata}
		}
	}

	if conns, ok := p.peerConns.Peek(); ok {
		for key, conn := range conns {
			if peer, ok := stat.Peers[string(key.id)]; ok {
				peer.Connections = append(peer.Connections, StatusRemotePeerConnection{
					Style:   key.style.String(),
					Address: conn.RemoteAddr().String(),
					RelayID: key.relayID,
				})
				stat.Peers[string(key.id)] = peer
			}
		}
	}

	for _, v := range stat.Peers {
		slices.SortFunc(v.Connections, func(a, b StatusRemotePeerConnection) int {
			return strings.Compare(a.Style, b.Style)
		})
	}

	return stat, nil
}

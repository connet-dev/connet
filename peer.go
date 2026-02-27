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
	"slices"
	"strings"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/certc"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/notify"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pbmodel"
	"github.com/quic-go/quic-go"
)

type peer struct {
	self *notify.V[*pbclient.Peer]

	relays     *notify.V[[]*pbclient.Relay]
	relayConns *notify.V[map[relayID]*quic.Conn]

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
		p.runShareRelays,
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

			tlsCfg, err := newServerTLSConfig(relay.ServerCertificate)
			if err != nil {
				return err
			}

			cfg := &relayConfig{tlsCfg, relay.Authentication}
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
		return nil, fmt.Errorf("server certificate parse: %w", err)
	}
	if len(cert.DNSNames) == 0 {
		return nil, fmt.Errorf("server certificate has no DNS names")
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
	keyTime = binary.BigEndian.AppendUint64(keyTime, uint64(time.Now().UnixNano()))

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
	if cfg == nil {
		return nil, fmt.Errorf("missing ecdh configuration")
	}

	remotes, ok := p.peers.Peek()
	if !ok {
		return nil, fmt.Errorf("no peers found")
	}
	var candidates []*x509.Certificate
	for _, remote := range remotes {
		cert, err := x509.ParseCertificate(remote.Peer.ServerCertificate)
		if err != nil {
			return nil, fmt.Errorf("peer certificate parse: %w", err)
		}
		if len(cert.DNSNames) == 0 {
			return nil, fmt.Errorf("peer certificate has no DNS names")
		}
		if cert.DNSNames[0] == cfg.ClientName {
			candidates = append(candidates, cert)
		}
	}

	switch len(candidates) {
	case 0:
		return nil, fmt.Errorf("peer not found")
	case 1:
		// we expect exactly one candidate, continue
	default:
		return nil, fmt.Errorf("multiple peers found")
	}

	certPublic, ok := candidates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("peer certificate has unexpected public key type %T", candidates[0].PublicKey)
	}
	if len(cfg.KeyTime) != 40 { // expected size is 32 (ECDG public key) + 8 (timestamp)
		return nil, fmt.Errorf("keytime length check failed: %d", len(cfg.KeyTime))
	}
	if !ed25519.Verify(certPublic, cfg.KeyTime, cfg.Signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	keyBytes, timeBytes := cfg.KeyTime[0:len(cfg.KeyTime)-8], cfg.KeyTime[len(cfg.KeyTime)-8:]
	t := time.Unix(0, int64(binary.BigEndian.Uint64(timeBytes)))
	if time.Since(t).Abs() > 5*time.Minute {
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
	Relays map[string]StatusRelay `json:"relays"`
	// Peers shows the status of each peer this peer is connected to
	Peers map[string]StatusRemotePeer `json:"peers"`
}

type StatusRelay struct {
	ID         string   `json:"id"`
	Hostports  []string `json:"hostports"`
	Metadata   string   `json:"metadata"`
	Connection string   `json:"connection"`
}

type StatusRemotePeer struct {
	ID          string                       `json:"id"`
	Metadata    string                       `json:"metadata"`
	DirectAddrs []string                     `json:"direct-addresses"`
	Connections []StatusRemotePeerConnection `json:"connections"`
}

type StatusRemotePeerConnection struct {
	Style   string `json:"style"`
	Address string `json:"address"`
	RelayID string `json:"relay-id,omitempty"`
}

func (p *peer) status() (StatusPeer, error) {
	stat := StatusPeer{
		Relays: map[string]StatusRelay{},
		Peers:  map[string]StatusRemotePeer{},
	}

	if relays, ok := p.relays.Peek(); ok {
		for _, relay := range relays {
			stat.Relays[relay.Id] = StatusRelay{
				ID:        relay.Id,
				Metadata:  relay.Metadata,
				Hostports: iterc.MapSliceStrings(model.HostPortFromPBs(relay.Addresses)),
			}
		}
	}

	if relayConns, ok := p.relayConns.Peek(); ok {
		for id, conn := range relayConns {
			if v, ok := stat.Relays[string(id)]; ok {
				v.Connection = conn.RemoteAddr().String()
				stat.Relays[string(id)] = v
			}
		}
	}

	if peers, ok := p.peers.Peek(); ok {
		for _, peer := range peers {
			stat.Peers[peer.Id] = StatusRemotePeer{
				ID:       peer.Id,
				Metadata: peer.Metadata,
				DirectAddrs: iterc.MapSlice(peer.Peer.Directs, func(addr *pbmodel.AddrPort) string {
					naddr, err := addr.AsNetip()
					if err != nil {
						return fmt.Sprintf("invalid address: %v", err)
					}
					return naddr.String()
				}),
			}
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

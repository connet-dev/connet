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

	"github.com/connet-dev/connet/certc"
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
	self       *notify.V[*pbclient.Peer]
	relays     *notify.V[[]*pbclient.Relay]
	relayConns *notify.V[map[relayID]*quic.Conn]
	peers      *notify.V[[]*pbclient.RemotePeer]
	peerConns  *notify.V[map[peerConnKey]*quic.Conn]

	direct      *directServer
	addrs       *notify.V[advertiseAddrs]
	allowDirect bool

	serverCert tls.Certificate
	clientCert tls.Certificate
	logger     *slog.Logger
}

type peerID string

type peerConnKey struct {
	id    peerID
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

func newPeer(direct *directServer, addrs *notify.V[advertiseAddrs], allowDirect bool, logger *slog.Logger) (*peer, error) {
	root, err := certc.NewRoot()
	if err != nil {
		return nil, err
	}

	serverCert, err := root.NewServer(certc.CertOpts{
		Domains: []string{netc.GenDomainName("connet-direct")},
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

	if allowDirect {
		direct.addServerCert(serverTLSCert)
	}

	return &peer{
		self: notify.New(&pbclient.Peer{
			ServerCertificate: serverTLSCert.Leaf.Raw,
			ClientCertificate: clientTLSCert.Leaf.Raw,
		}),
		relays:     notify.NewEmpty[[]*pbclient.Relay](),
		relayConns: notify.New(map[relayID]*quic.Conn{}),
		peers:      notify.NewEmpty[[]*pbclient.RemotePeer](),
		peerConns:  notify.New(map[peerConnKey]*quic.Conn{}),

		direct:      direct,
		addrs:       addrs,
		allowDirect: allowDirect,

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
	if !p.allowDirect {
		return nil
	}

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

func (p *peer) addActiveConn(id peerID, style peerStyle, key string, conn *quic.Conn) {
	p.logger.Debug("add active connection", "peer", id, "style", style, "addr", conn.RemoteAddr())
	notify.MapPut(p.peerConns, peerConnKey{id, style, key}, conn)
}

func (p *peer) removeActiveConn(id peerID, style peerStyle, key string) {
	p.logger.Debug("remove active connection", "peer", id, "style", style)
	notify.MapDelete(p.peerConns, peerConnKey{id, style, key})
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
	remotes, err := p.peers.Peek()
	if err != nil {
		return nil, fmt.Errorf("peers peer: %w", err)
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
	// Status of each relay this peer is connected to
	Relays []StatusRelayConnection `json:"relays"`
	// Status of each peer this peer is connected to
	Peers []StatusPeerConnection `json:"peers"`
}

type StatusRelayConnection struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

type StatusPeerConnection struct {
	ID    string `json:"id"`
	Style string `json:"style"`
	Addr  string `json:"addr"`
}

func (p *peer) status() (StatusPeer, error) {
	stat := StatusPeer{}

	relays, err := p.relayConns.Peek()
	if err != nil {
		return StatusPeer{}, err
	}
	for id, conn := range relays {
		stat.Relays = append(stat.Relays, StatusRelayConnection{
			ID:   string(id),
			Addr: conn.RemoteAddr().String(),
		})
	}
	slices.SortFunc(stat.Relays, func(l, r StatusRelayConnection) int {
		return strings.Compare(l.ID, r.ID)
	})

	conns, err := p.peerConns.Peek()
	if err != nil {
		return StatusPeer{}, err
	}
	for key, conn := range conns {
		stat.Peers = append(stat.Peers, StatusPeerConnection{
			ID:    string(key.id),
			Style: key.style.String(),
			Addr:  conn.RemoteAddr().String(),
		})
	}
	slices.SortFunc(stat.Peers, func(l, r StatusPeerConnection) int {
		if diff := strings.Compare(l.ID, r.ID); diff != 0 {
			return diff
		}
		return strings.Compare(l.Style, r.Style)
	})

	return stat, nil
}

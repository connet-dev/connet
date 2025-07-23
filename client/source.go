package client

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/cryptoc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/reliable"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

// SourceConfig structure represents source configuration.
type SourceConfig struct {
	Endpoint         model.Endpoint
	Route            model.RouteOption
	RelayEncryptions []model.EncryptionScheme

	DestinationLB         model.LoadBalancer
	DestinationLBRetry    model.LoadBalancerRetry
	DestinationLBRetryMax int
}

// NewSourceConfig creates a source config for a given name.
func NewSourceConfig(name string) SourceConfig {
	return SourceConfig{
		Endpoint:           model.NewEndpoint(name),
		Route:              model.RouteAny,
		RelayEncryptions:   []model.EncryptionScheme{model.NoEncryption},
		DestinationLB:      model.LeastLatencyLB,
		DestinationLBRetry: model.AllRetry,
	}
}

// WithRoute sets the route option for this configuration.
func (cfg SourceConfig) WithRoute(route model.RouteOption) SourceConfig {
	cfg.Route = route
	return cfg
}

// WithRelayEncryptions sets the relay encryptions option for this configuration.
func (cfg SourceConfig) WithRelayEncryptions(schemes ...model.EncryptionScheme) SourceConfig {
	cfg.RelayEncryptions = schemes
	return cfg
}

func (cfg SourceConfig) WithDestinationLB(lb model.LoadBalancer, retry model.LoadBalancerRetry, max int) SourceConfig {
	cfg.DestinationLB = lb
	cfg.DestinationLBRetry = retry
	cfg.DestinationLBRetryMax = max
	return cfg
}

type Source struct {
	cfg    SourceConfig
	logger *slog.Logger

	peer  *peer
	conns atomic.Pointer[[]sourceConn]

	connsTracking   map[string]*atomic.Int32 // TODO add peer id type
	connsTrackingMu sync.RWMutex
	roundRobinIndex atomic.Int32
}

type sourceConn struct {
	peer peerConnKey
	conn *quic.Conn
}

func NewSource(cfg SourceConfig, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Source, error) {
	logger = logger.With("source", cfg.Endpoint)
	p, err := newPeer(direct, root, logger)
	if err != nil {
		return nil, err
	}
	if cfg.Route.AllowDirect() {
		p.expectDirect()
	}
	var connsTracking map[string]*atomic.Int32
	if cfg.DestinationLB == model.LeastConnsLB {
		connsTracking = map[string]*atomic.Int32{}
	}

	return &Source{
		cfg:    cfg,
		logger: logger,

		peer: p,

		connsTracking: connsTracking,
	}, nil
}

func (s *Source) Config() SourceConfig {
	return s.cfg
}

func (s *Source) RunPeer(ctx context.Context) error {
	return reliable.RunGroup(ctx,
		s.peer.run,
		s.runActive,
	)
}

func (s *Source) RunAnnounce(ctx context.Context, conn *quic.Conn, directAddrs *notify.V[AdvertiseAddrs], notifyResponse func(error)) error {
	pc := &peerControl{
		local:    s.peer,
		endpoint: s.cfg.Endpoint,
		role:     model.Source,
		opt:      s.cfg.Route,
		conn:     conn,
		notify:   notifyResponse,
	}

	if s.cfg.Route.AllowDirect() {
		g, ctx := errgroup.WithContext(ctx)
		g.Go(func() error {
			return directAddrs.Listen(ctx, func(t AdvertiseAddrs) error {
				s.peer.setDirectAddrs(t.All())
				return nil
			})
		})
		g.Go(func() error { return pc.run(ctx) })
		return g.Wait()
	}

	return pc.run(ctx)
}

func (s *Source) PeerStatus() (PeerStatus, error) {
	return s.peer.status()
}

func (s *Source) runActive(ctx context.Context) error {
	return s.peer.activeConnsListen(ctx, func(active map[peerConnKey]*quic.Conn) error {
		s.logger.Debug("active conns", "len", len(active))

		var conns = make([]sourceConn, 0, len(active))
		for peer, conn := range active {
			conns = append(conns, sourceConn{peer, conn})
		}
		s.conns.Store(&conns)
		return nil
	})
}

var ErrNoActiveDestinations = errors.New("no active destinations")

func (s *Source) findActive() ([]sourceConn, error) {
	conns := s.conns.Load()
	if conns == nil || len(*conns) == 0 {
		return nil, ErrNoActiveDestinations
	}

	return slices.SortedFunc(slices.Values(*conns), rttCompare), nil
}

func rttCompare(l, r sourceConn) int {
	switch {
	case l.peer.style == peerRelay && r.peer.style != peerRelay:
		return +1
	case l.peer.style != peerRelay && r.peer.style == peerRelay:
		return -1
	}

	var ld, rd = time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)

	if rtt := quicc.RTTStats(l.conn); rtt != nil {
		ld = rtt.SmoothedRTT()
	}
	if rtt := quicc.RTTStats(r.conn); rtt != nil {
		rd = rtt.SmoothedRTT()
	}

	return cmp.Compare(ld, rd)
}

type peerSourceConn struct {
	peerID string
	conns  []sourceConn
}

func (s *Source) findActiveByPeer() ([]peerSourceConn, error) {
	conns := s.conns.Load()
	if conns == nil || len(*conns) == 0 {
		return nil, ErrNoActiveDestinations
	}

	bypeer := map[string][]sourceConn{}
	for _, conn := range *conns {
		bypeer[conn.peer.id] = append(bypeer[conn.peer.id], conn)
	}
	peerConns := make([]peerSourceConn, 0, len(bypeer))
	for k, conns := range bypeer {
		slices.SortFunc(conns, rttCompare)
		peerConns = append(peerConns, peerSourceConn{k, conns})
	}

	switch s.cfg.DestinationLB {
	case model.LeastLatencyLB:
		return s.leastLatencySorted(peerConns), nil
	case model.LeastConnsLB:
		return s.leastConnsSortedByPeer(peerConns), nil
	case model.RoundRobinLB:
		return s.roundRobinSorted(peerConns), nil
	case model.RandomLB:
		return s.randomSorted(peerConns), nil
	default:
		return s.leastLatencySorted(peerConns), nil
	}
}

func (s *Source) leastLatencySorted(conns []peerSourceConn) []peerSourceConn {
	return slices.SortedFunc(slices.Values(conns), func(l, r peerSourceConn) int {
		return rttCompare(l.conns[0], r.conns[0])
	})
}

func (s *Source) leastConnsSortedByPeer(conns []peerSourceConn) []peerSourceConn {
	s.connsTrackingMu.RLock()
	connsTracking := maps.Clone(s.connsTracking)
	s.connsTrackingMu.RUnlock()

	byPeer := map[string]int32{}
	for k, c := range connsTracking {
		byPeer[k] = byPeer[k] + c.Load()
	}

	return slices.SortedFunc(slices.Values(conns), func(l, r peerSourceConn) int {
		var lcount, rcount int32
		if c, ok := byPeer[l.peerID]; ok {
			lcount = c
		}
		if c, ok := byPeer[r.peerID]; ok {
			rcount = c
		}

		connCmp := lcount - rcount
		if connCmp != 0 {
			return int(connCmp)
		}

		return rttCompare(l.conns[0], r.conns[0])
	})
}

func (s *Source) roundRobinSorted(conns []peerSourceConn) []peerSourceConn {
	slices.SortStableFunc(conns, func(l, r peerSourceConn) int {
		return strings.Compare(l.peerID, r.peerID)
	})

	startFrom := int(s.roundRobinIndex.Add(1)) % len(conns)
	return append(conns[startFrom:], conns[:startFrom]...)
}

func (s *Source) randomSorted(conns []peerSourceConn) []peerSourceConn {
	random := make([]peerSourceConn, 0, len(conns))
	for len(conns) > 0 {
		ix := rand.IntN(len(conns))
		random = append(random, conns[ix])
		conns = slices.Delete(conns, ix, ix+1)
	}
	return random
}

func (s *Source) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

var ErrNoDialedDestinations = errors.New("no dialed destinations")

func (s *Source) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if s.cfg.DestinationLB == model.NoLB {
		conns, err := s.findActive()
		if err != nil {
			return nil, fmt.Errorf("get active conns: %w", err)
		}
		return s.dialInOrder(ctx, conns)
	}

	peerConns, err := s.findActiveByPeer()
	if err != nil {
		return nil, fmt.Errorf("get active conns: %w", err)
	}
	conns := make([]sourceConn, len(peerConns))
	for i, pconn := range peerConns {
		conns[i] = pconn.conns[0]
	}

	switch s.cfg.DestinationLBRetry {
	case model.NeverRetry:
		conns = conns[0:1]
	case model.CountRetry:
		maxLen := min(len(conns), s.cfg.DestinationLBRetryMax)
		conns = conns[0:maxLen]
	case model.TimedRetry:
		cancelCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.DestinationLBRetryMax)*time.Second)
		defer cancel()
		ctx = cancelCtx
	}

	return s.dialInOrder(ctx, conns)
}

func (s *Source) dialInOrder(ctx context.Context, conns []sourceConn) (net.Conn, error) {
	var errs []error
	for _, dest := range conns {
		if conn, err := s.dial(ctx, dest); err != nil {
			s.logger.Debug("could not dial destination", "err", err)
			errs = append(errs, err)
		} else {
			// connect was success
			return conn, nil
		}
	}

	return nil, fmt.Errorf("%w: %w", ErrNoDialedDestinations, errors.Join(errs...))
}

func (s *Source) dial(ctx context.Context, dest sourceConn) (net.Conn, error) {
	stream, err := dest.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("source connect open stream: %w", err)
	}
	conn, err := s.dialStream(ctx, dest, stream)
	if err != nil {
		if err := stream.Close(); err != nil {
			s.logger.Debug("could not close stream on error", "err", err)
		}
		return nil, err
	}

	if s.cfg.DestinationLB == model.LeastConnsLB {
		s.connsTrackingMu.RLock()
		counter, ok := s.connsTracking[dest.peer.id]
		if ok {
			counter.Add(1)
		}
		s.connsTrackingMu.RUnlock()

		if !ok {
			s.connsTrackingMu.Lock()
			counter, ok = s.connsTracking[dest.peer.id]
			if !ok {
				counter = &atomic.Int32{}
				s.connsTracking[dest.peer.id] = counter
			}
			counter.Add(1)
			s.connsTrackingMu.Unlock()
		}

		context.AfterFunc(stream.Context(), func() {
			counter.Add(-1)
		})
	}

	return conn, nil
}

func (s *Source) dialStream(ctx context.Context, dest sourceConn, stream *quic.Stream) (net.Conn, error) {
	var srcSecret *ecdh.PrivateKey

	connect := &pbconnect.Request_Connect{}
	if dest.peer.style == peerRelay {
		connect.SourceEncryption = model.PBFromEncryptions(s.cfg.RelayEncryptions)

		if slices.Contains(s.cfg.RelayEncryptions, model.TLSEncryption) {
			connect.SourceTls = &pbconnect.TLSConfiguration{
				ClientName: s.peer.serverCert.Leaf.DNSNames[0],
			}
		}

		if slices.Contains(s.cfg.RelayEncryptions, model.DHXCPEncryption) {
			secret, cfg, err := s.peer.newECDHConfig()
			if err != nil {
				return nil, fmt.Errorf("new ecdh config: %w", err)
			}

			connect.SourceDhX25519 = cfg
			srcSecret = secret
		}
	}

	if err := proto.Write(stream, &pbconnect.Request{
		Connect: connect,
	}); err != nil {
		return nil, fmt.Errorf("source connect write request: %w", err)
	}

	resp, err := pbconnect.ReadResponse(stream)
	if err != nil {
		return nil, fmt.Errorf("source connect read response: %w", err)
	}

	var encStream = quicc.StreamConn(stream, dest.conn)
	if dest.peer.style == peerRelay {
		destinationEncryption := model.EncryptionFromPB(resp.Connect.DestinationEncryption)
		if !slices.Contains(s.cfg.RelayEncryptions, destinationEncryption) {
			return nil, fmt.Errorf("source failed to negotiate encryption scheme: %s", destinationEncryption)
		}

		switch destinationEncryption {
		case model.TLSEncryption:
			s.logger.Debug("upgrading relay connection to TLS", "peer", dest.peer.id)
			dstConfig, err := s.getDestinationTLS(resp.Connect.DestinationTls.ClientName)
			if err != nil {
				return nil, fmt.Errorf("source tls: %w", err)
			}

			tlsConn := tls.Client(quicc.StreamConn(stream, dest.conn), dstConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("source handshake: %w", err)
			}

			encStream = tlsConn
		case model.DHXCPEncryption:
			s.logger.Debug("upgrading relay connection to DHXCP", "peer", dest.peer.id)
			dstPublic, err := s.peer.getECDHPublicKey(resp.Connect.DestinationDhX25519)
			if err != nil {
				return nil, fmt.Errorf("source public key: %w", err)
			}

			streamer, err := cryptoc.NewStreamer(srcSecret, dstPublic, true)
			if err != nil {
				return nil, fmt.Errorf("new streamer: %w", err)
			}

			encStream = streamer(stream)
		case model.NoEncryption:
			// nothing to do
		default:
			return nil, fmt.Errorf("source returned unknown encryption: %s", destinationEncryption)
		}
	}

	s.logger.Debug("dialed conn", "style", dest.peer.style)
	proxyProto := model.ProxyVersionFromPB(resp.GetConnect().GetProxyProto())
	return proxyProto.Wrap(encStream), nil
}

func (s *Source) getDestinationTLS(name string) (*tls.Config, error) {
	remotes, err := s.peer.peers.Peek()
	if err != nil {
		return nil, fmt.Errorf("destination peers list: %w", err)
	}

	for _, remote := range remotes {
		switch cfg, err := newServerTLSConfig(remote.Peer.ServerCertificate); {
		case err != nil:
			return nil, fmt.Errorf("destination peer server cert: %w", err)
		case cfg.name == name:
			return &tls.Config{
				Certificates: []tls.Certificate{s.peer.clientCert},
				RootCAs:      cfg.cas,
				ServerName:   cfg.name,
			}, nil
		}
	}

	return nil, fmt.Errorf("destination peer %s not found", name)
}

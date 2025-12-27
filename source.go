package connet

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/cryptoc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/statusc"
	"github.com/quic-go/quic-go"
)

var ErrSourceClosed = fmt.Errorf("source closed: %w", errEndpointClosed)
var ErrSourceConnect = errors.New("cannot connect destination")
var ErrSourceConnectDestinations = fmt.Errorf("%w: all peer connections were unreachable", ErrSourceConnect)
var ErrSourceNoActiveDestinations = fmt.Errorf("%w: no active peer connections", ErrSourceConnect)

// Source represents an endpoint that can connect to remote destinations.
// It is compatible with [net.Dialer] on top of connet infrastructure
type Source struct {
	cfg SourceConfig
	ep  *endpoint

	conns           atomic.Pointer[[]sourceConn]
	connsTracking   map[peerID]*atomic.Int32
	connsTrackingMu sync.RWMutex
	roundRobinIndex atomic.Int32

	logger *slog.Logger
}

type sourceConn struct {
	peer peerConnKey
	conn *quic.Conn
}

func newSource(ctx context.Context, cl *Client, cfg SourceConfig) (*Source, error) {
	logger := cl.logger.With("source", cfg.Endpoint)

	ep, err := newEndpoint(ctx, cl, cfg.endpointConfig(), logger)
	if err != nil {
		return nil, err
	}

	var connsTracking map[peerID]*atomic.Int32
	if cfg.DestinationPolicy == model.LeastConnsPolicy {
		connsTracking = map[peerID]*atomic.Int32{}
	}

	src := &Source{
		cfg: cfg,
		ep:  ep,

		connsTracking: connsTracking,

		logger: logger,
	}

	go src.runActive(ep.ctx)

	return src, nil
}

// Dial calls [Source.DialContext] with [context.Background]
func (s *Source) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

// DialContext dials into any available destination. Both network and address are ignored.
// Blocks until connection can be established.
func (s *Source) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if s.cfg.DestinationPolicy == model.NoPolicy {
		conns, err := s.findActive()
		if err != nil {
			return nil, fmt.Errorf("find active conns: %w", err)
		}
		return s.dialInOrder(ctx, conns)
	}

	peerConns, err := s.findActiveByPeer()
	if err != nil {
		return nil, fmt.Errorf("find active conns by peer: %w", err)
	}
	conns := make([]sourceConn, len(peerConns))
	for i, pconn := range peerConns {
		conns[i] = pconn.conns[0]
	}

	switch s.cfg.DestinationRetry {
	case model.NeverRetry:
		conns = conns[0:1]
	case model.CountRetry:
		maxLen := min(len(conns), s.cfg.DestinationRetryMax)
		conns = conns[0:maxLen]
	case model.TimedRetry:
		cancelCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.DestinationRetryMax)*time.Millisecond)
		defer cancel()
		ctx = cancelCtx
	}

	return s.dialInOrder(ctx, conns)
}

// Config returns the original [SourceConfig] used to start this source
func (s *Source) Config() SourceConfig {
	return s.cfg
}

// Context returns [context.Context] associated with the lifetime of this source.
// Once the source is closed, this context will be canceled
func (s *Source) Context() context.Context {
	return s.ep.ctx
}

// SourceStatus describes the status of a source
type SourceStatus struct {
	// Overall status of this source
	Status statusc.Status `json:"status"`
	// Peer status for this source
	StatusPeer
}

// Status returns the current status of this source
func (s *Source) Status() (SourceStatus, error) {
	stat, err := s.ep.status()
	return SourceStatus(stat), err
}

// Close closes this source. Any active connections are also closed.
func (s *Source) Close() error {
	return s.ep.close(ErrSourceClosed)
}

func (s *Source) runActive(ctx context.Context) {
	if err := s.runActiveErr(ctx); err != nil {
		s.logger.Debug("run active exited", "err", err) // TODO
	}
}

func (s *Source) runActiveErr(ctx context.Context) error {
	return s.ep.peer.activeConnsListen(ctx, func(active map[peerConnKey]*quic.Conn) error {
		s.logger.Debug("active conns", "len", len(active))

		var conns = make([]sourceConn, 0, len(active))
		for peer, conn := range active {
			if peer.style != peerRelayIncoming {
				conns = append(conns, sourceConn{peer, conn})
			}
		}
		s.conns.Store(&conns)
		return nil
	})
}

func (s *Source) getDestinationTLS(name string) (*tls.Config, error) {
	remotes, err := s.ep.peer.peers.Peek()
	if err != nil {
		return nil, fmt.Errorf("destination peers list: %w", err)
	}

	for _, remote := range remotes {
		switch cfg, err := newServerTLSConfig(remote.Peer.ServerCertificate); {
		case err != nil:
			return nil, fmt.Errorf("destination peer server cert: %w", err)
		case cfg.name == name:
			return &tls.Config{
				Certificates: []tls.Certificate{s.ep.peer.clientCert},
				RootCAs:      cfg.cas,
				ServerName:   cfg.name,
			}, nil
		}
	}

	return nil, fmt.Errorf("destination peer %s not found", name)
}

func (s *Source) findActive() ([]sourceConn, error) {
	conns := s.conns.Load()
	if conns == nil || len(*conns) == 0 {
		return nil, ErrSourceNoActiveDestinations
	}

	return slices.SortedFunc(slices.Values(*conns), rttCompare), nil
}

func rttCompare(l, r sourceConn) int {
	switch {
	case l.peer.style.isRelay() && r.peer.style.isDirect():
		return +1
	case l.peer.style.isDirect() && r.peer.style.isRelay():
		return -1
	}

	ld := r.conn.ConnectionStats().SmoothedRTT
	rd := r.conn.ConnectionStats().SmoothedRTT

	return cmp.Compare(ld, rd)
}

type peerSourceConn struct {
	id    peerID
	conns []sourceConn
}

func (s *Source) findActiveByPeer() ([]peerSourceConn, error) {
	conns := s.conns.Load()
	if conns == nil || len(*conns) == 0 {
		return nil, ErrSourceNoActiveDestinations
	}

	bypeer := map[peerID][]sourceConn{}
	for _, conn := range *conns {
		bypeer[conn.peer.id] = append(bypeer[conn.peer.id], conn)
	}
	peerConns := make([]peerSourceConn, 0, len(bypeer))
	for k, conns := range bypeer {
		slices.SortFunc(conns, rttCompare)
		peerConns = append(peerConns, peerSourceConn{k, conns})
	}

	switch s.cfg.DestinationPolicy {
	case model.LeastLatencyPolicy:
		return s.leastLatencySorted(peerConns), nil
	case model.LeastConnsPolicy:
		return s.leastConnsSortedByPeer(peerConns), nil
	case model.RoundRobinPolicy:
		return s.roundRobinSorted(peerConns), nil
	case model.RandomPolicy:
		return s.randomSorted(peerConns), nil
	default:
		return peerConns, nil
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

	byPeer := map[peerID]int32{}
	for k, c := range connsTracking {
		byPeer[k] = byPeer[k] + c.Load()
	}

	return slices.SortedFunc(slices.Values(conns), func(l, r peerSourceConn) int {
		var lcount, rcount int32
		if c, ok := byPeer[l.id]; ok {
			lcount = c
		}
		if c, ok := byPeer[r.id]; ok {
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
		return strings.Compare(string(l.id), string(r.id))
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

	return nil, fmt.Errorf("%w: %w", ErrSourceConnectDestinations, errors.Join(errs...))
}

func (s *Source) dial(ctx context.Context, dest sourceConn) (net.Conn, error) {
	if s.cfg.DialTimeout > 0 {
		timeoutCtx, timeoutCancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
		ctx = timeoutCtx
		defer timeoutCancel()
	}

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

	if s.cfg.DestinationPolicy == model.LeastConnsPolicy {
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
	if dest.peer.style.isRelay() {
		connect.SourceEncryption = model.PBFromEncryptions(s.cfg.RelayEncryptions)

		if slices.Contains(s.cfg.RelayEncryptions, model.TLSEncryption) {
			connect.SourceTls = &pbconnect.TLSConfiguration{
				ClientName: s.ep.peer.serverCert.Leaf.DNSNames[0],
			}
		}

		if slices.Contains(s.cfg.RelayEncryptions, model.DHXCPEncryption) {
			secret, cfg, err := s.ep.peer.newECDHConfig()
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
	if dest.peer.style.isRelay() {
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
			dstPublic, err := s.ep.peer.getECDHPublicKey(resp.Connect.DestinationDhX25519)
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

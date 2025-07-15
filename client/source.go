package client

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"slices"
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
	Endpoint            model.Endpoint
	Route               model.RouteOption
	RelayEncryptions    []model.EncryptionScheme
	DestinationBalancer model.LoadBalancer
}

// NewSourceConfig creates a source config for a given name.
func NewSourceConfig(name string) SourceConfig {
	return SourceConfig{
		Endpoint:            model.NewEndpoint(name),
		Route:               model.RouteAny,
		RelayEncryptions:    []model.EncryptionScheme{model.NoEncryption},
		DestinationBalancer: model.FindFastestBalancer,
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

func (cfg SourceConfig) WithDestinationBalancer(balancer model.LoadBalancer) SourceConfig {
	cfg.DestinationBalancer = balancer
	return cfg
}

type Source struct {
	cfg    SourceConfig
	logger *slog.Logger

	peer  *peer
	conns atomic.Pointer[[]sourceConn]
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

	return &Source{
		cfg:    cfg,
		logger: logger,

		peer: p,
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

func connCompare(l, r sourceConn) int {
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

var ErrNoActiveDestinations = errors.New("no active destinations")

func (s *Source) findActive() ([]sourceConn, error) {
	conns := s.conns.Load()
	if conns == nil || len(*conns) == 0 {
		return nil, ErrNoActiveDestinations
	}

	return slices.SortedFunc(slices.Values(*conns), connCompare), nil
}

func (s *Source) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

var ErrNoDialedDestinations = errors.New("no dialed destinations")

func (s *Source) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conns, err := s.findActive()
	if err != nil {
		return nil, fmt.Errorf("get active conns: %w", err)
	}

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

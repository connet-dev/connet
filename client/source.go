package client

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type SourceConfig struct {
	Forward model.Forward
	Address string
	Route   model.RouteOption
}

func NewSourceConfig(name string, addr string) SourceConfig {
	return SourceConfig{Forward: model.NewForward(name), Address: addr, Route: model.RouteAny}
}

func (cfg SourceConfig) WithRoute(route model.RouteOption) SourceConfig {
	cfg.Route = route
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
	conn quic.Connection
}

func NewSource(cfg SourceConfig, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Source, error) {
	logger = logger.With("source", cfg.Forward)
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

func (s *Source) SetDirectAddrs(addrs []netip.AddrPort) {
	if !s.cfg.Route.AllowDirect() {
		return
	}

	s.peer.setDirectAddrs(addrs)
}

func (s *Source) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runServer(ctx) })
	g.Go(func() error { return s.peer.run(ctx) })
	g.Go(func() error { return s.runActive(ctx) })

	return g.Wait()
}

func (s *Source) Status() (PeerStatus, error) {
	return s.peer.status()
}

func (s *Source) runActive(ctx context.Context) error {
	return s.peer.activeConnsListen(ctx, func(active map[peerConnKey]quic.Connection) error {
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

var errNoActiveConns = errors.New("no active conns")

func (s *Source) findActive() ([]sourceConn, error) {
	conns := s.conns.Load()
	if conns == nil || len(*conns) == 0 {
		return nil, errNoActiveConns
	}

	return slices.SortedFunc(slices.Values(*conns), connCompare), nil
}

func (s *Source) runServer(ctx context.Context) error {
	s.logger.Debug("starting server", "addr", s.cfg.Address)
	l, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("server listen: %w", err)
	}
	defer l.Close()

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	s.logger.Info("listening for conns")
	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("server accept: %w", err)
		}

		go s.runConn(ctx, conn)
	}
}

func (s *Source) runConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	s.logger.Debug("received conn", "remote", conn.RemoteAddr())

	if err := s.runConnErr(ctx, conn); err != nil {
		s.logger.Warn("error handling conn", "err", err)
	}
}

var errNoDesinationRoute = errors.New("no route to destination")

func (s *Source) runConnErr(ctx context.Context, conn net.Conn) error {
	conns, err := s.findActive()
	if err != nil {
		return fmt.Errorf("get active conns: %w", err)
	}

	for _, dest := range conns {
		if err := s.connectDestination(ctx, conn, dest); err != nil {
			s.logger.Debug("could not dial destination", "err", err)
		} else {
			// connect was success
			return nil
		}
	}

	return errNoDesinationRoute
}

func (s *Source) connectDestination(ctx context.Context, conn net.Conn, dest sourceConn) error {
	stream, err := dest.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("source connect open stream: %w", err)
	}
	defer stream.Close()

	connect := &pbc.Request_Connect{}
	if dest.peer.style == peerRelay {
		connect.SourceClientName = s.peer.serverCert.Leaf.DNSNames[0]
		connect.SourceEncryption = []pbc.RelayEncryptionScheme{pbc.RelayEncryptionScheme_TLS}
	}

	if err := pb.Write(stream, &pbc.Request{
		Connect: connect,
	}); err != nil {
		return fmt.Errorf("source connect write request: %w", err)
	}

	resp, err := pbc.ReadResponse(stream)
	if err != nil {
		return fmt.Errorf("source connect read response: %w", err)
	}

	var encStream io.ReadWriteCloser = stream
	if dest.peer.style == peerRelay && resp.Connect.DestinationEncryption == pbc.RelayEncryptionScheme_TLS {
		dstConfig, err := s.getDestinationTLS(resp.Connect.DestinationClientName)
		if err != nil {
			return fmt.Errorf("source tls: %w", err)
		}

		tlsConn := tls.Client(&quicc.StreamConn{
			Stream: stream,
			// TODO addrs
		}, dstConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("source handshake: %w", err)
		}

		encStream = tlsConn
	}

	proxy := model.ProxyVersionFromPB(resp.GetConnect().GetProxyProto())
	if err := proxy.Write(encStream, conn); err != nil {
		return fmt.Errorf("source write proxy header: %w", err)
	}

	s.logger.Debug("joining conns", "style", dest.peer.style)
	err = netc.Join(ctx, conn, encStream)
	s.logger.Debug("disconnected conns", "err", err)

	return nil
}

func (s *Source) RunControl(ctx context.Context, conn quic.Connection) error {
	return (&peerControl{
		local: s.peer,
		fwd:   s.cfg.Forward,
		role:  model.Source,
		opt:   s.cfg.Route,
		conn:  conn,
	}).run(ctx)
}

func (s *Source) getDestinationTLS(name string) (*tls.Config, error) {
	peers, err := s.peer.peers.Peek()
	if err != nil {
		return nil, fmt.Errorf("destination peers list: %w", err)
	}

	for _, peer := range peers {
		cfg, err := newServerTLSConfig(peer.ServerCertificate)
		if err != nil {
			return nil, fmt.Errorf("destination peer server cert: %w", err)
		}
		if cfg.name == name {
			return &tls.Config{
				Certificates: []tls.Certificate{s.peer.clientCert},
				RootCAs:      cfg.cas,
				ServerName:   cfg.name,
			}, nil
		}
	}

	return nil, fmt.Errorf("destination peer %s not found", name)
}

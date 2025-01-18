package client

import (
	"cmp"
	"context"
	"log/slog"
	"maps"
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
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Source struct {
	fwd    model.Forward
	addr   string
	opt    model.RouteOption
	logger *slog.Logger

	peer  *peer
	conns atomic.Pointer[[]sourceConn]
}

type sourceConn struct {
	peer peerConnKey
	conn quic.Connection
}

func NewSource(fwd model.Forward, addr string, opt model.RouteOption, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Source, error) {
	logger = logger.With("source", fwd)
	p, err := newPeer(direct, root, logger)
	if err != nil {
		return nil, err
	}
	if opt.AllowDirect() {
		p.expectDirect()
	}

	return &Source{
		fwd:    fwd,
		addr:   addr,
		opt:    opt,
		logger: logger,

		peer: p,
	}, nil
}

func (s *Source) SetDirectAddrs(addrs []netip.AddrPort) {
	if !s.opt.AllowDirect() {
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
		activePeers := slices.SortedFunc(maps.Keys(active), func(l, r peerConnKey) int {
			return int(l.style - r.style)
		})

		var conns = make([]sourceConn, len(activePeers))
		for i, peer := range activePeers {
			conns[i] = sourceConn{peer, active[peer]}
		}
		s.conns.Store(&conns)
		return nil
	})
}

func (s *Source) findActive() ([]sourceConn, error) {
	conns := s.conns.Load()
	if conns == nil || len(*conns) == 0 {
		return nil, kleverr.New("no active conns")
	}

	return slices.SortedFunc(slices.Values(*conns), func(l, r sourceConn) int {
		var ld, rd = time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)

		if rtt := quicc.RTTStats(l.conn); rtt != nil {
			ld = rtt.SmoothedRTT()
		}
		if rtt := quicc.RTTStats(r.conn); rtt != nil {
			rd = rtt.SmoothedRTT()
		}

		return cmp.Compare(ld, rd)
	}), nil
}

func (s *Source) runServer(ctx context.Context) error {
	s.logger.Debug("starting server", "addr", s.addr)
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
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
			return kleverr.Ret(err)
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

func (s *Source) runConnErr(ctx context.Context, conn net.Conn) error {
	conns, err := s.findActive()
	if err != nil {
		return kleverr.Newf("could not get active conns: %w", err)
	}

	for _, dest := range conns {
		if err := s.connectDestination(ctx, conn, dest); err != nil {
			s.logger.Debug("could not dial destination", "err", err)
		} else {
			// connect was success
			return nil
		}
	}

	return kleverr.New("could not find route to destination")
}

func (s *Source) connectDestination(ctx context.Context, conn net.Conn, dest sourceConn) error {
	stream, err := dest.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Newf("could not find route: %w", err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbc.Request{
		Connect: &pbc.Request_Connect{},
	}); err != nil {
		return kleverr.Newf("could not write request: %w", err)
	}

	if _, err := pbc.ReadResponse(stream); err != nil {
		return kleverr.Newf("could not read response: %w", err)
	}

	s.logger.Debug("joining to server")
	err = netc.Join(ctx, conn, stream)
	s.logger.Debug("disconnected to server", "err", err)

	return nil
}

func (s *Source) RunControl(ctx context.Context, conn quic.Connection) error {
	return (&peerControl{
		local: s.peer,
		fwd:   s.fwd,
		role:  model.Source,
		opt:   s.opt,
		conn:  conn,
	}).run(ctx)
}

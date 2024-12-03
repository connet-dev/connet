package client

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Source struct {
	fwd    model.Forward
	addr   string
	opt    model.RouteOption
	logger *slog.Logger

	peer *peer
}

func NewSource(fwd model.Forward, addr string, opt model.RouteOption, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Source, error) {
	p, err := newPeer(direct, root, logger.With("source", fwd))
	if err != nil {
		return nil, err
	}

	return &Source{
		fwd:    fwd,
		addr:   addr,
		opt:    opt,
		logger: logger.With("source", fwd),

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

func (s *Source) runActive(ctx context.Context) error {
	return s.peer.activeConnsListen(ctx, func(active map[peerConnKey]quic.Connection) error {
		s.logger.Debug("active conns", "len", len(active))
		return nil
	})
}

func (s *Source) findActive(ctx context.Context) (quic.Stream, error) {
	active := s.peer.getActiveConns()
	activeKeys := slices.SortedFunc(maps.Keys(active), func(l, r peerConnKey) int {
		return int(l.style - r.style)
	})
	for _, peer := range activeKeys {
		conn := active[peer]
		if stream, err := conn.OpenStreamSync(ctx); err != nil {
			// not active
		} else {
			s.logger.Debug("found active conn", "peer", peer.id, "style", peer.style)
			return stream, nil
		}
	}
	return nil, kleverr.New("could not find conn")
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
	stream, err := s.findActive(ctx)
	if err != nil {
		return kleverr.Newf("could not find route: %w", err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbc.Request{
		Connect: &pbc.Request_Connect{
			To: s.fwd.PB(),
		},
	}); err != nil {
		return kleverr.Newf("could not write request: %w", err)
	}

	resp, err := pbc.ReadResponse(stream)
	if err != nil {
		return kleverr.Newf("could not read response: %w", err)
	}

	s.logger.Debug("joining to server", "connect", resp)
	err = netc.Join(ctx, conn, stream)
	s.logger.Debug("disconnected to server", "err", err)

	return nil
}

func (s *Source) RunControl(ctx context.Context, conn quic.Connection) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runControl(ctx, conn) })
	if s.opt.AllowRelay() {
		g.Go(func() error { return s.runRelay(ctx, conn) })
	}

	return g.Wait()
}

func (s *Source) runControl(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	})

	g.Go(func() error {
		defer s.logger.Debug("completed source notify")
		return s.peer.selfListen(ctx, func(peer *pbs.ClientPeer) error {
			directLen := 0
			if peer.Direct != nil {
				directLen = len(peer.Direct.Addresses)
			}
			s.logger.Debug("updated source", "direct", directLen, "relay", len(peer.Relays))
			return pb.Write(stream, &pbs.Request{
				Source: &pbs.Request_Source{
					To:     s.fwd.PB(),
					Source: peer,
				},
			})
		})
	})

	g.Go(func() error {
		for {
			resp, err := pbs.ReadResponse(stream)
			if err != nil {
				return err
			}
			if resp.Source == nil {
				return kleverr.Newf("unexpected response")
			}

			s.peer.setPeers(resp.Source.Destinations)
		}
	})

	return g.Wait()
}

func (s *Source) runRelay(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		SourceRelay: &pbs.Request_SourceRelay{
			To:          s.fwd.PB(),
			Certificate: s.peer.clientCert.Leaf.Raw,
		},
	}); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	})

	g.Go(func() error {
		for {
			resp, err := pbs.ReadResponse(stream)
			if err != nil {
				return err
			}
			if resp.Relay == nil {
				return kleverr.Newf("unexpected response")
			}

			s.peer.setRelays(resp.Relay.Relays)
		}
	})

	return g.Wait()
}

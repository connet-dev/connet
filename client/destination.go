package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Destination struct {
	fwd    model.Forward
	addr   string
	opt    model.RouteOption
	logger *slog.Logger

	peer  *peer
	conns map[peerConnKey]*destinationConn
}

func NewDestination(fwd model.Forward, addr string, opt model.RouteOption, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Destination, error) {
	logger = logger.With("destination", fwd)
	p, err := newPeer(direct, root, logger)
	if err != nil {
		return nil, err
	}
	if opt.AllowDirect() {
		p.expectDirect()
	}

	return &Destination{
		fwd:    fwd,
		addr:   addr,
		opt:    opt,
		logger: logger,

		peer:  p,
		conns: map[peerConnKey]*destinationConn{},
	}, nil
}

func (d *Destination) SetDirectAddrs(addrs []netip.AddrPort) {
	if !d.opt.AllowDirect() {
		return
	}

	d.peer.setDirectAddrs(addrs)
}

func (d *Destination) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return d.peer.run(ctx) })
	g.Go(func() error { return d.runActive(ctx) })

	return g.Wait()
}

func (d *Destination) Status() (PeerStatus, error) {
	return d.peer.status()
}

func (d *Destination) runActive(ctx context.Context) error {
	return d.peer.activeConnsListen(ctx, func(active map[peerConnKey]quic.Connection) error {
		d.logger.Debug("active conns", "len", len(active))
		for peer, conn := range active {
			if dc := d.conns[peer]; dc != nil {
				if dc.conn == conn {
					continue
				}
				dc.close()
				delete(d.conns, peer)
			}

			dc := newDestinationConn(d, peer, conn)
			d.conns[peer] = dc
			go dc.run(ctx)
		}

		for peer, conn := range d.conns {
			if _, ok := active[peer]; !ok {
				conn.close()
				delete(d.conns, peer)
			}
		}
		return nil
	})
}

type destinationConn struct {
	dst  *Destination
	peer peerConnKey
	conn quic.Connection

	closer chan struct{}
}

func newDestinationConn(dst *Destination, peer peerConnKey, conn quic.Connection) *destinationConn {
	return &destinationConn{dst, peer, conn, make(chan struct{})}
}

func (d *destinationConn) run(ctx context.Context) {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			stream, err := d.conn.AcceptStream(ctx)
			if err != nil {
				d.dst.logger.Debug("accept failed", "peer", d.peer.id, "style", d.peer.style, "err", err)
				return err
			}
			d.dst.logger.Debug("accepted stream from", "peer", d.peer.id, "style", d.peer.style)
			go d.dst.runDestination(ctx, stream)
		}
	})
	g.Go(func() error {
		<-d.closer
		return errPeeringStop
	})

	if err := g.Wait(); err != nil {
		d.dst.logger.Debug("error while running destination", "err", err)
	}
}

func (d *destinationConn) close() {
	close(d.closer)
}

func (d *Destination) runDestination(ctx context.Context, stream quic.Stream) {
	defer stream.Close()

	if err := d.runDestinationErr(ctx, stream); err != nil {
		d.logger.Debug("done destination")
	}
}

func (d *Destination) runDestinationErr(ctx context.Context, stream quic.Stream) error {
	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Connect != nil:
		return d.runConnect(ctx, stream)
	case req.Heartbeat != nil:
		return d.heartbeat(ctx, stream, req.Heartbeat)
	default:
		err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return kleverr.Newf("cannot write error response: %w", err)
		}
		return err
	}
}

func (d *Destination) runConnect(ctx context.Context, stream quic.Stream) error {
	// TODO check allow from?

	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		err := pb.NewError(pb.Error_DestinationDialFailed, "%s could not be dialed: %v", d.fwd, err)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}
	defer conn.Close()

	if err := pb.Write(stream, &pbc.Response{}); err != nil {
		return kleverr.Newf("could not write response: %w", err)
	}

	d.logger.Debug("joining from server")
	err = netc.Join(ctx, stream, conn)
	d.logger.Debug("disconnected from server", "err", err)

	return nil
}

func (d *Destination) heartbeat(ctx context.Context, stream quic.Stream, hbt *pbc.Heartbeat) error {
	if err := pb.Write(stream, &pbc.Response{Heartbeat: hbt}); err != nil {
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
			req, err := pbc.ReadRequest(stream)
			if err != nil {
				return err
			}
			if req.Heartbeat == nil {
				respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
				if err := pb.Write(stream, &pbc.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			if err := pb.Write(stream, &pbc.Response{Heartbeat: req.Heartbeat}); err != nil {
				return err
			}
		}
	})

	return g.Wait()
}

func (d *Destination) RunControl(ctx context.Context, conn quic.Connection) error {
	return (&peerControl{
		local: d.peer,
		fwd:   d.fwd,
		role:  model.Destination,
		opt:   d.opt,
		conn:  conn,
	}).run(ctx)
}

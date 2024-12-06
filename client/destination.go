package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

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

func (d *Destination) runActive(ctx context.Context) error {
	return d.peer.activeConnsListen(ctx, func(active map[peerConnKey]quic.Connection) error {
		d.logger.Debug("active conns", "len", len(active))
		for peer, conn := range active {
			if dc := d.conns[peer]; dc != nil {
				// TODO update conn?
				continue
			}
			dc := &destinationConn{d, peer, conn}
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
}

func (d *destinationConn) run(ctx context.Context) {
	for {
		stream, err := d.conn.AcceptStream(ctx)
		if err != nil {
			d.dst.logger.Debug("accept failed", "peer", d.peer.id, "style", d.peer.style, "err", err)
			return
		}
		d.dst.logger.Debug("accepted stream from", "peer", d.peer.id, "style", d.peer.style)
		go d.dst.runDestination(ctx, stream)
	}
}

func (d *destinationConn) close() {
	d.conn.CloseWithError(1, "done")
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
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return d.runControl(ctx, conn) })
	if d.opt.AllowRelay() {
		g.Go(func() error { return d.runRelay(ctx, conn) })
	}

	return g.Wait()
}

func (d *Destination) runControl(ctx context.Context, conn quic.Connection) error {
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
		defer d.logger.Debug("completed destination notify")
		return d.peer.selfListen(ctx, func(peer *pbs.ClientPeer) error {
			directLen := 0
			if peer.Direct != nil {
				directLen = len(peer.Direct.Addresses)
			}
			d.logger.Debug("updated destination", "direct", directLen, "relay", len(peer.Relays))
			return pb.Write(stream, &pbs.Request{
				Destination: &pbs.Request_Destination{
					From: d.fwd.PB(),
					Peer: peer,
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
			if resp.Destination == nil {
				return kleverr.Newf("unexpected response")
			}

			// TODO on server restart peers is reset and client loses active peers
			// only for them to come back at the next tick, with different ID
			d.peer.setPeers(resp.Destination.Peers)
		}
	})

	return g.Wait()
}

func (d *Destination) runRelay(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		DestinationRelay: &pbs.Request_DestinationRelay{
			From:              d.fwd.PB(),
			ClientCertificate: d.peer.clientCert.Leaf.Raw,
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

			d.peer.setRelays(resp.Relay.Relays)
		}
	})

	return g.Wait()
}

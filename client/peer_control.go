package client

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/slogc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type DirectAddrs struct {
	STUN  []netip.AddrPort
	Local []netip.AddrPort
	PMP   []netip.AddrPort
}

func (d DirectAddrs) All() []netip.AddrPort {
	addrs := make([]netip.AddrPort, 0, len(d.STUN)+len(d.Local)+len(d.PMP))
	addrs = append(addrs, d.STUN...)
	addrs = append(addrs, d.Local...)
	addrs = append(addrs, d.PMP...)
	return addrs
}

type peerControl struct {
	local    *peer
	endpoint model.Endpoint
	role     model.Role
	opt      model.RouteOption
	conn     *quic.Conn
	notify   func(error)
}

func (d *peerControl) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return d.runAnnounce(ctx) })
	if d.opt.AllowRelay() {
		g.Go(func() error { return d.runRelay(ctx) })
	}

	return g.Wait()
}

func (d *peerControl) runAnnounce(ctx context.Context) error {
	stream, err := d.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("announce open stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(d.local.logger, "error closing announce stream", "err", err)
		}
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	})

	g.Go(func() error {
		defer d.local.logger.Debug("completed announce notify")
		return d.local.selfListen(ctx, func(peer *pbclient.Peer) error {
			d.local.logger.Debug("updated announce", "direct", len(peer.Directs), "relays", len(peer.RelayIds))
			return proto.Write(stream, &pbclient.Request{
				Announce: &pbclient.Request_Announce{
					Endpoint: d.endpoint.PB(),
					Role:     d.role.PB(),
					Peer:     peer,
				},
			})
		})
	})

	g.Go(func() error {
		for {
			resp, err := pbclient.ReadResponse(stream)
			d.notify(err)
			if err != nil {
				return err
			}
			if resp.Announce == nil {
				return fmt.Errorf("announce unexpected response")
			}

			// TODO on server restart peers is reset and client loses active peers
			// only for them to come back at the next tick, with different ID
			d.local.setPeers(resp.Announce.Peers)
		}
	})

	return g.Wait()
}

func (d *peerControl) runRelay(ctx context.Context) error {
	stream, err := d.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("relay open stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(d.local.logger, "error closing relay stream", "err", err)
		}
	}()

	if err := proto.Write(stream, &pbclient.Request{
		Relay: &pbclient.Request_Relay{
			Endpoint:          d.endpoint.PB(),
			Role:              d.role.PB(),
			ClientCertificate: d.local.clientCert.Leaf.Raw,
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
			resp, err := pbclient.ReadResponse(stream)
			if err != nil {
				d.notify(err)
				return err
			}
			if resp.Relay == nil {
				return fmt.Errorf("relay unexpected response")
			}

			d.local.setRelays(resp.Relay.Relays)
		}
	})

	return g.Wait()
}

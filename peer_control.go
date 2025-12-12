package connet

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/slogc"
	"golang.org/x/sync/errgroup"
)

type advertiseAddrs struct {
	STUN  []netip.AddrPort
	PMP   []netip.AddrPort
	Local []netip.AddrPort
}

func (d advertiseAddrs) all() []netip.AddrPort {
	addrs := make([]netip.AddrPort, 0, len(d.STUN)+len(d.PMP)+len(d.Local))
	addrs = append(addrs, d.STUN...)
	addrs = append(addrs, d.PMP...)
	addrs = append(addrs, d.Local...)
	return addrs
}

type peerControl struct {
	local *peer

	endpoint model.Endpoint
	role     model.Role
	opt      model.RouteOption

	sess   *session
	notify func(error)
}

func (d *peerControl) run(ctx context.Context) error {
	g := reliable.NewGroup(ctx)

	g.Go(d.runAnnounce)

	if d.opt.AllowDirect() {
		g.Go(d.runDirectAddrs)
	}

	if d.opt.AllowRelay() {
		g.Go(d.runRelay)
	}

	return g.Wait()
}

func (d *peerControl) runAnnounce(ctx context.Context) error {
	stream, err := d.sess.conn.OpenStreamSync(ctx)
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

func (d *peerControl) runDirectAddrs(ctx context.Context) error {
	return d.sess.addrs.Listen(ctx, func(t advertiseAddrs) error {
		d.local.setDirectAddrs(t.all())
		return nil
	})
}

func (d *peerControl) runRelay(ctx context.Context) error {
	stream, err := d.sess.conn.OpenStreamSync(ctx)
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

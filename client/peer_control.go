package client

import (
	"context"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type peerControl struct {
	local *peer
	fwd   model.Forward
	role  model.Role
	opt   model.RouteOption
	conn  quic.Connection
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
		defer d.local.logger.Debug("completed announce notify")
		return d.local.selfListen(ctx, func(peer *pbs.ClientPeer) error {
			directLen := 0
			if peer.Direct != nil {
				directLen = len(peer.Direct.Addresses)
			}
			d.local.logger.Debug("updated announce", "direct", directLen, "relay", len(peer.Relays))
			return pb.Write(stream, &pbs.Request{
				Announce: &pbs.Request_Announce{
					Forward: d.fwd.PB(),
					Role:    d.role.PB(),
					Peer:    peer,
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
			if resp.Announce == nil {
				return kleverr.Newf("unexpected response")
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
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		Relay: &pbs.Request_Relay{
			Forward:           d.fwd.PB(),
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
			resp, err := pbs.ReadResponse(stream)
			if err != nil {
				return err
			}
			if resp.Relay == nil {
				return kleverr.Newf("unexpected response")
			}

			d.local.setRelays(resp.Relay.Relays)
		}
	})

	return g.Wait()
}

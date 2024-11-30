package client

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Destination struct {
	fwd  model.Forward
	addr string
	opt  model.RouteOption

	serverCert *certc.Cert
	clientCert *certc.Cert
	logger     *slog.Logger

	peer *peer
}

func NewDestination(fwd model.Forward, addr string, opt model.RouteOption, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Destination, error) {
	serverCert, err := root.NewServer(certc.CertOpts{Domains: []string{"connet-direct"}})
	if err != nil {
		return nil, err
	}
	clientCert, err := root.NewClient(certc.CertOpts{})
	if err != nil {
		return nil, err
	}

	return &Destination{
		fwd:  fwd,
		addr: addr,
		opt:  opt,

		serverCert: serverCert,
		clientCert: clientCert,
		logger:     logger.With("destination", fwd),

		peer: newPeer(),
	}, nil
}

func (d *Destination) SetDirectAddrs(addrs []netip.AddrPort) {
	if !d.opt.AllowDirect() {
		return
	}

	d.peer.setDirect(&pbs.DirectRoute{
		Addresses:         pb.AsAddrPorts(addrs),
		ServerCertificate: d.serverCert.Raw(),
		ClientCertificate: d.clientCert.Raw(),
	})
}

func (d *Destination) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return d.runPeers(ctx) })

	return g.Wait()
}

func (d *Destination) runPeers(ctx context.Context) error {
	return d.peer.peersListen(ctx, func(peers []*pbs.ServerPeer) error {
		d.logger.Debug("sources updated", "peers", len(peers))
		return nil
	})
}

func (d *Destination) RunRelay(ctx context.Context, conn quic.Connection) error {
	if !d.opt.AllowRelay() {
		return nil
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		DestinationRelay: &pbs.Request_DestinationRelay{
			From:        d.fwd.PB(),
			Certificate: d.clientCert.Raw(),
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

func (d *Destination) RunControl(ctx context.Context, conn quic.Connection) error {
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
			d.logger.Debug("updated destination", "direct", len(peer.Direct.Addresses), "relay", len(peer.Relays))
			return pb.Write(stream, &pbs.Request{
				Destination: &pbs.Request_Destination{
					From:        d.fwd.PB(),
					Destination: peer,
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

			d.peer.setPeers(resp.Destination.Sources)
		}
	})

	return g.Wait()
}

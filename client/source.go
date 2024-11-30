package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Source struct {
	fwd  model.Forward
	addr string
	opt  model.RouteOption

	serverCert *certc.Cert
	clientCert *certc.Cert
	logger     *slog.Logger

	peer *peer
}

func NewSource(fwd model.Forward, addr string, opt model.RouteOption, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Source, error) {
	serverCert, err := root.NewServer(certc.CertOpts{Domains: []string{"connet-direct"}})
	if err != nil {
		return nil, err
	}
	clientCert, err := root.NewClient(certc.CertOpts{})
	if err != nil {
		return nil, err
	}

	return &Source{
		fwd:  fwd,
		addr: addr,
		opt:  opt,

		serverCert: serverCert,
		clientCert: clientCert,
		logger:     logger.With("source", fwd),

		peer: newPeer(),
	}, nil
}

func (s *Source) SetDirectAddrs(addrs []netip.AddrPort) {
	if !s.opt.AllowDirect() {
		return
	}

	s.peer.setDirect(&pbs.DirectRoute{
		Addresses:         pb.AsAddrPorts(addrs),
		ServerCertificate: s.serverCert.Raw(),
		ClientCertificate: s.clientCert.Raw(),
	})
}

func (s *Source) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runPeers(ctx) })

	return g.Wait()
}

func (s *Source) runPeers(ctx context.Context) error {
	return s.peer.peersListen(ctx, func(peers []*pbs.ServerPeer) error {
		s.logger.Debug("destinations updated", "peers", len(peers))
		return nil
	})
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

		go func() {
			defer conn.Close()
		}()
		// go s.runConn(ctx, conn)
	}
}

func (s *Source) RunRelay(ctx context.Context, conn quic.Connection) error {
	if !s.opt.AllowRelay() {
		return nil
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		SourceRelay: &pbs.Request_SourceRelay{
			To:          s.fwd.PB(),
			Certificate: s.clientCert.Raw(),
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

func (s *Source) RunControl(ctx context.Context, conn quic.Connection) error {
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
			s.logger.Debug("updated source", "direct", len(peer.Direct.Addresses), "relay", len(peer.Relays))
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

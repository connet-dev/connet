package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Destination struct {
	fwd  model.Forward
	addr string
	opt  model.RouteOption

	serverCert    *certc.Cert
	clientCert    *certc.Cert
	clientTLSCert tls.Certificate
	transport     *quic.Transport
	logger        *slog.Logger

	active       map[netip.AddrPort]quic.Connection
	activeMu     sync.RWMutex
	activeNotify *notify.N

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
	clientTLSCert, err := clientCert.TLSCert()
	if err != nil {
		return nil, err
	}

	return &Destination{
		fwd:  fwd,
		addr: addr,
		opt:  opt,

		serverCert:    serverCert,
		clientCert:    clientCert,
		clientTLSCert: clientTLSCert,
		transport:     direct.transport, // TODO
		logger:        logger.With("destination", fwd),

		active:       map[netip.AddrPort]quic.Connection{},
		activeNotify: notify.New(),

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
	g.Go(func() error { return d.runActive(ctx) })

	return g.Wait()
}

func (d *Destination) runPeers(ctx context.Context) error {
	return d.peer.peersListen(ctx, func(peers []*pbs.ServerPeer) error {
		d.logger.Debug("sources updated", "peers", len(peers))
		for _, p := range peers {
			go d.runPeerDirect(ctx, p)
			go d.runPeerRelay(ctx, p)
		}
		return nil
	})
}

func (d *Destination) runActive(ctx context.Context) error {
	return d.activeNotify.Listen(ctx, func() error {
		active := d.getActive()
		d.logger.Debug("active conns", "len", len(active))
		for addr, conn := range active {
			go func() {
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						d.logger.Debug("accept failed", "addr", addr)
						return
					}
					go d.runDestination(ctx, stream)
				}
			}()
		}
		return nil
	})
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
		return d.runConnect(ctx, stream, model.NewForwardFromPB(req.Connect.To))
	default:
		err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return kleverr.Newf("cannot write error response: %w", err)
		}
		return err
	}
}

func (d *Destination) runConnect(ctx context.Context, stream quic.Stream, target model.Forward) error {
	if d.fwd != target {
		err := pb.NewError(pb.Error_DestinationNotFound, "%s not found on this client", target)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	// TODO check allow from?

	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		err := pb.NewError(pb.Error_DestinationDialFailed, "%s could not be dialed: %v", target, err)
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

func (d *Destination) addActive(ap netip.AddrPort, conn quic.Connection) {
	defer d.activeNotify.Updated()

	d.activeMu.Lock()
	defer d.activeMu.Unlock()

	d.active[ap] = conn
}

func (d *Destination) getActive() map[netip.AddrPort]quic.Connection {
	d.activeMu.Lock()
	defer d.activeMu.Unlock()

	return maps.Clone(d.active)
}

func (d *Destination) runPeerDirect(ctx context.Context, peer *pbs.ServerPeer) error {
	for _, paddr := range peer.Direct.Addresses {
		d.logger.Debug("dialing direct", "addr", paddr.AsNetip())
		addr := net.UDPAddrFromAddrPort(paddr.AsNetip())

		directCert, err := x509.ParseCertificate(peer.Direct.ServerCertificate)
		if err != nil {
			return err
		}
		directCAs := x509.NewCertPool()
		directCAs.AddCert(directCert)

		conn, err := d.transport.Dial(ctx, addr, &tls.Config{
			Certificates: []tls.Certificate{d.clientTLSCert},
			RootCAs:      directCAs,
			ServerName:   "connet-direct",
			NextProtos:   []string{"connet-direct"},
		}, &quic.Config{
			KeepAlivePeriod: 25 * time.Second,
		})
		if err != nil {
			d.logger.Debug("could not direct dial", "addr", addr, "err", err)
			continue
		}
		d.addActive(paddr.AsNetip(), conn)
		break
	}
	return nil
}

func (d *Destination) runPeerRelay(ctx context.Context, peer *pbs.ServerPeer) error {
	for _, r := range peer.Relays {
		d.logger.Debug("dialing relay", "addr", r.Address.AsNetip())
		addr := net.UDPAddrFromAddrPort(r.Address.AsNetip())

		relayCert, err := x509.ParseCertificate(r.ServerCertificate)
		if err != nil {
			return err
		}
		relayCAs := x509.NewCertPool()
		relayCAs.AddCert(relayCert)

		conn, err := d.transport.Dial(ctx, addr, &tls.Config{
			Certificates: []tls.Certificate{d.clientTLSCert},
			RootCAs:      relayCAs,
			ServerName:   relayCert.DNSNames[0],
			NextProtos:   []string{"connet-relay"},
		}, &quic.Config{
			KeepAlivePeriod: 25 * time.Second,
		})
		if err != nil {
			d.logger.Debug("could not relay dial", "addr", r.Address.AsNetip(), "err", err)
			continue
		}
		d.addActive(r.Address.AsNetip(), conn)
	}
	return nil
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

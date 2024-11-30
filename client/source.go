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

type Source struct {
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

func NewSource(fwd model.Forward, addr string, opt model.RouteOption, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Source, error) {
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

	return &Source{
		fwd:  fwd,
		addr: addr,
		opt:  opt,

		serverCert:    serverCert,
		clientCert:    clientCert,
		clientTLSCert: clientTLSCert,
		transport:     direct.transport, // TODO
		logger:        logger.With("source", fwd),

		active:       map[netip.AddrPort]quic.Connection{},
		activeNotify: notify.New(),

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

	g.Go(func() error { return s.runServer(ctx) })
	g.Go(func() error { return s.runPeers(ctx) })
	g.Go(func() error { return s.runActive(ctx) })

	return g.Wait()
}

func (s *Source) runPeers(ctx context.Context) error {
	return s.peer.peersListen(ctx, func(peers []*pbs.ServerPeer) error {
		s.logger.Debug("destinations updated", "peers", len(peers))
		for _, p := range peers {
			go s.runPeerDirect(ctx, p)
			go s.runPeerRelay(ctx, p)
		}
		return nil
	})
}

func (s *Source) runActive(ctx context.Context) error {
	return s.activeNotify.Listen(ctx, func() error {
		active := s.getActive()
		s.logger.Debug("active conns", "len", len(active))
		return nil
	})
}

func (s *Source) addActive(ap netip.AddrPort, conn quic.Connection) {
	defer s.activeNotify.Updated()

	s.activeMu.Lock()
	defer s.activeMu.Unlock()

	s.active[ap] = conn
}

func (s *Source) getActive() map[netip.AddrPort]quic.Connection {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()

	return maps.Clone(s.active)
}

func (s *Source) findActive(ctx context.Context) (quic.Stream, error) {
	active := s.getActive()
	for _, conn := range active {
		if stream, err := conn.OpenStreamSync(ctx); err != nil {
			// not active
		} else {
			return stream, nil
		}
	}
	return nil, kleverr.New("could not find conn")
}

func (s *Source) runPeerDirect(ctx context.Context, peer *pbs.ServerPeer) error {
	for _, paddr := range peer.Direct.Addresses {
		s.logger.Debug("dialing direct", "addr", paddr.AsNetip())
		addr := net.UDPAddrFromAddrPort(paddr.AsNetip())

		directCert, err := x509.ParseCertificate(peer.Direct.ServerCertificate)
		if err != nil {
			return err
		}
		directCAs := x509.NewCertPool()
		directCAs.AddCert(directCert)

		conn, err := s.transport.Dial(ctx, addr, &tls.Config{
			Certificates: []tls.Certificate{s.clientTLSCert},
			RootCAs:      directCAs,
			ServerName:   "connet-direct",
			NextProtos:   []string{"connet-direct"},
		}, &quic.Config{
			KeepAlivePeriod: 25 * time.Second,
		})
		if err != nil {
			s.logger.Debug("could not direct dial", "addr", addr, "err", err)
			continue
		}
		s.addActive(paddr.AsNetip(), conn)
		break
	}
	return nil
}

func (s *Source) runPeerRelay(ctx context.Context, peer *pbs.ServerPeer) error {
	for _, r := range peer.Relays {
		s.logger.Debug("dialing relay", "addr", r.Address.AsNetip())
		addr := net.UDPAddrFromAddrPort(r.Address.AsNetip())

		relayCert, err := x509.ParseCertificate(r.ServerCertificate)
		if err != nil {
			return err
		}
		relayCAs := x509.NewCertPool()
		relayCAs.AddCert(relayCert)

		conn, err := s.transport.Dial(ctx, addr, &tls.Config{
			Certificates: []tls.Certificate{s.clientTLSCert},
			RootCAs:      relayCAs,
			ServerName:   relayCert.DNSNames[0],
			NextProtos:   []string{"connet-relay"},
		}, &quic.Config{
			KeepAlivePeriod: 25 * time.Second,
		})
		if err != nil {
			s.logger.Debug("could not relay dial", "addr", r.Address.AsNetip(), "err", err)
			continue
		}
		s.addActive(r.Address.AsNetip(), conn)
	}
	return nil
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

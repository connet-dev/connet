package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/keihaya-com/connet/authc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type controlConfig struct {
	addr   *net.UDPAddr
	auth   authc.Authenticator
	store  RelayStoreManager
	cert   tls.Certificate
	logger *slog.Logger
}

func newControlServer(cfg controlConfig) (*controlServer, error) {
	return &controlServer{
		addr:  cfg.addr,
		auth:  cfg.auth,
		store: cfg.store,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cfg.cert},
			NextProtos:   []string{"connet"},
		},
		logger: cfg.logger.With("control", cfg.addr),

		whispers: NewWhispers(),
	}, nil
}

type controlServer struct {
	addr    *net.UDPAddr
	auth    authc.Authenticator
	store   RelayStoreManager
	tlsConf *tls.Config
	logger  *slog.Logger

	whispers *Whispers
}

func (s *controlServer) Run(ctx context.Context) error {
	s.logger.Debug("start udp listener")
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer conn.Close()

	s.logger.Debug("start quic listener")
	tr := &quic.Transport{
		Conn: conn,
		// TODO review other options
	}
	defer tr.Close()

	l, err := tr.Listen(s.tlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return kleverr.Ret(err)
	}
	defer l.Close()

	s.logger.Info("waiting for connections")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				s.logger.Info("stopped quic server")
				return nil
			}
			continue
		}
		s.logger.Info("client connected", "local", conn.LocalAddr(), "remote", conn.RemoteAddr())

		cID := ksuid.New()
		cc := &controlConn{
			id:     cID,
			server: s,
			conn:   conn,
			logger: s.logger.With("conn-id", cID),
		}
		go cc.run(ctx)
	}
}

type controlConn struct {
	id     ksuid.KSUID
	server *controlServer
	conn   quic.Connection
	logger *slog.Logger

	auth authc.Authentication
}

func (c *controlConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (c *controlConn) runErr(ctx context.Context) error {
	if auth, err := c.authenticate(ctx); err != nil {
		c.conn.CloseWithError(1, "auth failed")
		return kleverr.Ret(err)
	} else {
		c.auth = auth
	}

	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			return err
		}

		sID := ksuid.New()
		cs := &controlStream{
			id:     sID,
			conn:   c,
			stream: stream,
			logger: c.logger.With("stream-id", sID),
		}
		go cs.run(ctx)
	}
}

var retAuth = kleverr.Ret1[authc.Authentication]

func (c *controlConn) authenticate(ctx context.Context) (authc.Authentication, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return retAuth(err)
	}
	defer authStream.Close()

	req := &pbs.Authenticate{}
	if err := pb.Read(authStream, req); err != nil {
		return retAuth(err)
	}

	auth, err := c.server.auth.Authenticate(req.Token)
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "Invalid or unknown token")
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retAuth(err)
		}
		return retAuth(err)
	}

	origin, err := pb.AddrPortFromNet(c.conn.RemoteAddr())
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "cannot resolve origin: %v", err)
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retAuth(err)
		}
		return retAuth(err)
	}

	if err := pb.Write(authStream, &pbs.AuthenticateResp{
		Public: origin,
	}); err != nil {
		return retAuth(err)
	}

	c.logger.Debug("authentication completed", "realms", auth.Realms, "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr())
	return auth, nil
}

type controlStream struct {
	id     ksuid.KSUID
	conn   *controlConn
	stream quic.Stream
	logger *slog.Logger
}

func (s *controlStream) run(ctx context.Context) {
	defer s.stream.Close()

	if err := s.runErr(ctx); err != nil {
		s.logger.Warn("error while running", "err", err)
	}
}

func (s *controlStream) runErr(ctx context.Context) error {
	req, err := pbs.ReadRequest(s.stream)
	if err != nil {
		return err
	}

	switch {
	case req.Relay != nil:
		return s.relay(ctx, req.Relay)
	case req.Destination != nil:
		return s.destination(ctx, req.Destination)
	case req.Source != nil:
		return s.source(ctx, req.Source)
	default:
		return s.unknown(ctx, req)
	}
}

func (s *controlStream) allowed(bind *pb.Binding) bool {
	return slices.Contains(s.conn.auth.Realms, bind.Realm)
}

func (s *controlStream) relay(ctx context.Context, req *pbs.Request_Relay) error {
	for _, dst := range req.Destinations {
		if !s.allowed(dst) {
			err := pb.NewError(pb.Error_Unknown, "desination %s.%s not allowed", dst.Name, dst.Realm)
			if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
				return kleverr.Newf("could not write error response: %w", err)
			}
			return err
		}
	}
	for _, src := range req.Sources {
		if !s.allowed(src) {
			err := pb.NewError(pb.Error_Unknown, "source %s.%s not allowed", src.Name, src.Realm)
			if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
				return kleverr.Newf("could not write error response: %w", err)
			}
			return err
		}
	}

	cert, err := x509.ParseCertificate(req.Certificate)
	if err != nil {
		err := pb.NewError(pb.Error_Unknown, "invalid certificate: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	s.conn.server.store.Add(cert, NewBindingsPB(req.Destinations), NewBindingsPB(req.Sources))
	defer s.conn.server.store.Remove(cert)
	// TODO how to remove?

	defer s.logger.Debug("completed relays notify")
	return s.conn.server.store.RelaysNotify(ctx, func(relays []string) error {
		s.logger.Debug("updated relays list", "relays", len(relays))
		var addrs []*pbs.RelayAddress
		for _, hostport := range relays {
			addrs = append(addrs, &pbs.RelayAddress{
				Hostport: hostport,
			})
		}

		if err := pb.Write(s.stream, &pbs.Response{
			Relay: &pbs.Response_Relay{
				Addresses: addrs,
			},
		}); err != nil {
			return kleverr.Ret(err)
		}
		return nil
	})
}

func (s *controlStream) destination(ctx context.Context, req *pbs.Request_Destination) error {
	if !s.allowed(req.Binding) {
		err := pb.NewError(pb.Error_Unknown, "desination %s.%s not allowed", req.Binding.Name, req.Binding.Realm)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	direct, relays, err := s.readDestination(req)
	if err != nil {
		respErr := pb.NewError(pb.Error_Unknown, "cannot parse certificate: %v", err)
		return pb.Write(s.stream, &pbs.Response{Error: respErr})
	}

	w := s.conn.server.whispers.For(NewBindingPB(req.Binding))
	w.AddDestination(s.conn.id, direct, relays)
	defer w.RemoveDestination(s.conn.id)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			req, err := pbs.ReadRequest(s.stream)
			if err != nil {
				return err
			}
			if req.Destination == nil {
				respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
				if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			direct, relays, err := s.readDestination(req.Destination)
			if err != nil {
				respErr := pb.NewError(pb.Error_Unknown, "cannot parse certificate: %v", err)
				return pb.Write(s.stream, &pbs.Response{Error: respErr})
			}

			w.AddDestination(s.conn.id, direct, relays)
		}
	})

	g.Go(func() error {
		defer s.logger.Debug("completed sources notify")
		return w.SourcesNotify(ctx, func(certs []*x509.Certificate) error {
			s.logger.Debug("updated sources list", "certs", len(certs))
			var certData [][]byte
			for _, cert := range certs {
				certData = append(certData, cert.Raw)
			}
			if err := pb.Write(s.stream, &pbs.Response{
				Destination: &pbs.Response_Destination{
					Certificates: certData,
				},
			}); err != nil {
				return kleverr.Ret(err)
			}
			return nil
		})
	})

	return g.Wait()
}

func (s *controlStream) readDestination(req *pbs.Request_Destination) (*DirectDestination, []RelayDestination, error) {
	var direct *DirectDestination
	var relays []RelayDestination

	if req.Direct != nil {
		cert, err := x509.ParseCertificate(req.Direct.Certificate)
		if err != nil {
			return nil, nil, err
		}
		direct = &DirectDestination{
			Addresses:   pb.AsNetips(req.Direct.Addresses),
			Certificate: cert,
		}
	}

	for _, r := range req.Relays {
		relays = append(relays, RelayDestination{
			Hostport: r.Hostport,
		})
	}

	return direct, relays, nil
}

func (s *controlStream) source(ctx context.Context, req *pbs.Request_Source) error {
	if !s.allowed(req.Binding) {
		err := pb.NewError(pb.Error_Unknown, "source %s.%s not allowed", req.Binding.Name, req.Binding.Realm)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	cert, err := x509.ParseCertificate(req.Certificate)
	if err != nil {
		respErr := pb.NewError(pb.Error_Unknown, "cannot parse certificate: %v", err)
		return pb.Write(s.stream, &pbs.Response{Error: respErr})
	}

	w := s.conn.server.whispers.For(NewBindingPB(req.Binding))
	w.AddSource(s.conn.id, cert)
	defer w.RemoveSource(s.conn.id)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			req, err := pbs.ReadRequest(s.stream)
			if err != nil {
				return err
			}
			if req.Source == nil {
				respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
				if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			cert, err := x509.ParseCertificate(req.Source.Certificate)
			if err != nil {
				respErr := pb.NewError(pb.Error_Unknown, "cannot parse certificate: %v", err)
				if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}
			w.AddSource(s.conn.id, cert)
		}
	})

	g.Go(func() error {
		defer s.logger.Debug("completed destinations notify")
		return w.DestinationsNotify(ctx, func(direct []DirectDestination, relays []RelayDestination) error {
			s.logger.Debug("updated destinations list", "direct", len(direct), "relay", len(relays))
			resp := &pbs.Response_Source{}

			for _, dst := range direct {
				resp.Directs = append(resp.Directs, &pbs.DirectAddress{
					Addresses:   pb.AsAddrPorts(dst.Addresses),
					Certificate: dst.Certificate.Raw,
				})
			}
			for _, dst := range relays {
				resp.Relays = append(resp.Relays, &pbs.RelayAddress{
					Hostport: dst.Hostport,
				})
			}

			if err := pb.Write(s.stream, &pbs.Response{
				Source: resp,
			}); err != nil {
				return kleverr.Ret(err)
			}
			return nil
		})
	})

	return g.Wait()
}

func (s *controlStream) unknown(ctx context.Context, req *pbs.Request) error {
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(s.stream, &pbc.Response{Error: err})
}

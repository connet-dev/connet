package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
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

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr())
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

func (s *controlStream) relay(ctx context.Context, req *pbs.Request_Relay) error {
	var destinations []Forward
	for _, dst := range req.Destinations {
		fwd := NewForwardFromPB(dst)
		if !s.conn.auth.AllowDestination(fwd.String()) {
			err := pb.NewError(pb.Error_RelayDestinationNotAllowed, "desination '%s' not allowed", fwd)
			if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
				return kleverr.Newf("could not write error response: %w", err)
			}
			return err
		}
		destinations = append(destinations, fwd)
	}

	var sources []Forward
	for _, src := range req.Sources {
		fwd := NewForwardFromPB(src)
		if !s.conn.auth.AllowSource(fwd.String()) {
			err := pb.NewError(pb.Error_RelaySourceNotAllowed, "source '%s' not allowed", fwd)
			if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
				return kleverr.Newf("could not write error response: %w", err)
			}
			return err
		}
		sources = append(sources, fwd)
	}

	cert, err := x509.ParseCertificate(req.Certificate)
	if err != nil {
		err := pb.NewError(pb.Error_RelayInvalidCertificate, "invalid certificate: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	s.conn.server.store.Add(cert, destinations, sources)
	defer s.conn.server.store.Remove(cert)
	// TODO how to remove?

	defer s.logger.Debug("completed relays notify")
	return s.conn.server.store.RelaysNotify(ctx, func(relays []string) error {
		s.logger.Debug("updated relays list", "relays", len(relays))
		var addrs []*pbs.Route
		for _, hostport := range relays {
			addrs = append(addrs, &pbs.Route{
				Hostport: hostport,
			})
		}

		if err := pb.Write(s.stream, &pbs.Response{
			Relay: &pbs.Response_Relay{
				Relays: addrs,
			},
		}); err != nil {
			return kleverr.Ret(err)
		}
		return nil
	})
}

func (s *controlStream) destination(ctx context.Context, req *pbs.Request_Destination) error {
	from := NewForwardFromPB(req.From)
	if !s.conn.auth.AllowDestination(from.String()) {
		err := pb.NewError(pb.Error_DestinationNotAllowed, "desination '%s' not allowed", from)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	direct, relays, err := s.readDestination(req)
	if err != nil {
		respErr := pb.NewError(pb.Error_DestinationInvalidCertificate, "cannot parse certificate: %v", err)
		return pb.Write(s.stream, &pbs.Response{Error: respErr})
	}

	w := s.conn.server.whispers.For(from)
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
				respErr := pb.NewError(pb.Error_DestinationInvalidCertificate, "cannot parse certificate: %v", err)
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

func (s *controlStream) readDestination(req *pbs.Request_Destination) ([]Route, []Route, error) {
	var directs []Route
	var relays []Route

	for _, d := range req.Directs {
		cert, err := x509.ParseCertificate(d.Certificate)
		if err != nil {
			return nil, nil, err
		}
		directs = append(directs, Route{
			Hostport:    d.Hostport,
			Certificate: cert,
		})
	}

	for _, r := range req.Relays {
		relays = append(relays, Route{
			Hostport: r.Hostport,
		})
	}

	return directs, relays, nil
}

func (s *controlStream) source(ctx context.Context, req *pbs.Request_Source) error {
	to := NewForwardFromPB(req.To)
	if !s.conn.auth.AllowSource(to.String()) {
		err := pb.NewError(pb.Error_SourceNotAllowed, "source '%s' not allowed", to)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	cert, err := x509.ParseCertificate(req.Certificate)
	if err != nil {
		respErr := pb.NewError(pb.Error_SourceInvalidCertificate, "cannot parse certificate: %v", err)
		return pb.Write(s.stream, &pbs.Response{Error: respErr})
	}

	w := s.conn.server.whispers.For(to)
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
				respErr := pb.NewError(pb.Error_SourceInvalidCertificate, "cannot parse certificate: %v", err)
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
		return w.DestinationsNotify(ctx, func(direct []Route, relays []Route) error {
			s.logger.Debug("updated destinations list", "direct", len(direct), "relay", len(relays))
			resp := &pbs.Response_Source{}

			for _, dst := range direct {
				resp.Directs = append(resp.Directs, &pbs.Route{
					Hostport:    dst.Hostport,
					Certificate: dst.Certificate.Raw,
				})
			}
			for _, dst := range relays {
				resp.Relays = append(resp.Relays, &pbs.Route{
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

package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr   *net.UDPAddr
	Cert   tls.Certificate
	Auth   Authenticator
	Relays Relays
	Logger *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	return &Server{
		addr:   cfg.Addr,
		auth:   cfg.Auth,
		relays: cfg.Relays,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cfg.Cert},
			NextProtos:   []string{"connet"},
		},
		logger: cfg.Logger.With("control", cfg.Addr),

		whisperer: newWhisperer(),
	}, nil
}

type Server struct {
	addr    *net.UDPAddr
	auth    Authenticator
	relays  Relays
	tlsConf *tls.Config
	logger  *slog.Logger

	whisperer *whisperer
}

func (s *Server) Run(ctx context.Context) error {
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
			if errors.Is(err, context.Canceled) {
				err = context.Cause(ctx)
			}
			s.logger.Warn("accept error", "err", err)
			return kleverr.Ret(err)
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
	server *Server
	conn   quic.Connection
	logger *slog.Logger

	auth Authentication
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

var retAuth = kleverr.Ret1[Authentication]

func (c *controlConn) authenticate(ctx context.Context) (Authentication, error) {
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
	case req.DestinationRelay != nil:
		return s.destinationRelay(ctx, req.DestinationRelay)
	case req.Destination != nil:
		return s.destination(ctx, req.Destination)
	case req.SourceRelay != nil:
		return s.sourceRelay(ctx, req.SourceRelay)
	case req.Source != nil:
		return s.source(ctx, req.Source)
	default:
		return s.unknown(ctx, req)
	}
}

func (s *controlStream) destinationRelay(ctx context.Context, req *pbs.Request_DestinationRelay) error {
	fwd := model.NewForwardFromPB(req.From)
	if !s.conn.auth.AllowDestination(fwd.String()) {
		err := pb.NewError(pb.Error_RelayDestinationNotAllowed, "desination '%s' not allowed", fwd)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	clientCert, err := x509.ParseCertificate(req.ClientCertificate)
	if err != nil {
		err := pb.NewError(pb.Error_RelayInvalidCertificate, "invalid certificate: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	serverCert, err := s.conn.server.relays.AddDestination(fwd, clientCert)
	if err != nil {
		err := pb.NewError(pb.Error_Unknown, "certificate create failed: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}
	defer s.conn.server.relays.RemoveDestination(fwd, clientCert)

	defer s.logger.Debug("completed destination relay notify")
	return s.conn.server.relays.Active(ctx, func(relays map[model.HostPort]struct{}) error {
		s.logger.Debug("updated destination relay list", "relays", len(relays))

		var addrs []*pb.HostPort
		for hp := range relays {
			addrs = append(addrs, hp.PB())
		}

		if err := pb.Write(s.stream, &pbs.Response{
			Relay: &pbs.Relays{
				Addresses:         addrs,
				ServerCertificate: serverCert.Raw,
			},
		}); err != nil {
			return kleverr.Ret(err)
		}
		return nil
	})
}

func validateDestinationCert(from model.Forward, peer *pbs.ClientPeer) *pb.Error {
	if peer.Direct == nil {
		return nil
	}
	if _, err := x509.ParseCertificate(peer.Direct.ClientCertificate); err != nil {
		return pb.NewError(pb.Error_DestinationInvalidCertificate, "desination '%s' client cert is invalid", from)
	}
	if _, err := x509.ParseCertificate(peer.Direct.ServerCertificate); err != nil {
		return pb.NewError(pb.Error_DestinationInvalidCertificate, "desination '%s' client cert is invalid", from)
	}
	return nil
}

func (s *controlStream) destination(ctx context.Context, req *pbs.Request_Destination) error {
	from := model.NewForwardFromPB(req.From)
	if !s.conn.auth.AllowDestination(from.String()) {
		err := pb.NewError(pb.Error_DestinationNotAllowed, "desination '%s' not allowed", from)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	if err := validateDestinationCert(from, req.Peer); err != nil {
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	w := s.conn.server.whisperer.For(from)
	w.AddDestination(s.conn.id, req.Peer)
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

			if err := validateDestinationCert(from, req.Destination.Peer); err != nil {
				if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
					return kleverr.Newf("could not write error response: %w", err)
				}
				return err
			}

			w.AddDestination(s.conn.id, req.Destination.Peer)
		}
	})

	g.Go(func() error {
		defer s.logger.Debug("completed sources notify")
		return w.Sources(ctx, func(peers []*pbs.ServerPeer) error {
			s.logger.Debug("updated sources list", "peers", len(peers))

			if err := pb.Write(s.stream, &pbs.Response{
				Destination: &pbs.Response_Destination{
					Peers: peers,
				},
			}); err != nil {
				return kleverr.Ret(err)
			}

			return nil
		})
	})

	return g.Wait()
}

func (s *controlStream) sourceRelay(ctx context.Context, req *pbs.Request_SourceRelay) error {
	fwd := model.NewForwardFromPB(req.To)
	if !s.conn.auth.AllowSource(fwd.String()) {
		err := pb.NewError(pb.Error_RelaySourceNotAllowed, "source '%s' not allowed", fwd)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	clientCert, err := x509.ParseCertificate(req.ClientCertificate)
	if err != nil {
		err := pb.NewError(pb.Error_RelayInvalidCertificate, "invalid certificate: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	serverCert, err := s.conn.server.relays.AddSource(fwd, clientCert)
	if err != nil {
		err := pb.NewError(pb.Error_Unknown, "certificate create failed: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}
	defer s.conn.server.relays.RemoveSource(fwd, clientCert)

	defer s.logger.Debug("completed source relay notify")
	return s.conn.server.relays.Active(ctx, func(relays map[model.HostPort]struct{}) error {
		s.logger.Debug("updated source relay list", "relays", len(relays))

		var addrs []*pb.HostPort
		for hp := range relays {
			addrs = append(addrs, hp.PB())
		}

		if err := pb.Write(s.stream, &pbs.Response{
			Relay: &pbs.Relays{
				Addresses:         addrs,
				ServerCertificate: serverCert.Raw,
			},
		}); err != nil {
			return kleverr.Ret(err)
		}
		return nil
	})
}

func validateSourceCert(to model.Forward, peer *pbs.ClientPeer) *pb.Error {
	if peer.Direct == nil {
		return nil
	}
	if _, err := x509.ParseCertificate(peer.Direct.ServerCertificate); err != nil {
		return pb.NewError(pb.Error_SourceInvalidCertificate, "source '%s' server cert is invalid", to)
	}
	if _, err := x509.ParseCertificate(peer.Direct.ClientCertificate); err != nil {
		return pb.NewError(pb.Error_SourceInvalidCertificate, "source '%s' client cert is invalid", to)
	}
	return nil
}

func (s *controlStream) source(ctx context.Context, req *pbs.Request_Source) error {
	to := model.NewForwardFromPB(req.To)
	if !s.conn.auth.AllowSource(to.String()) {
		err := pb.NewError(pb.Error_SourceNotAllowed, "source '%s' not allowed", to)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	if err := validateSourceCert(to, req.Peer); err != nil {
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	w := s.conn.server.whisperer.For(to)
	w.AddSource(s.conn.id, req.Peer)
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

			if err := validateSourceCert(to, req.Source.Peer); err != nil {
				if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
					return kleverr.Newf("could not write error response: %w", err)
				}
				return err
			}

			w.AddSource(s.conn.id, req.Source.Peer)
		}
	})

	g.Go(func() error {
		defer s.logger.Debug("completed destinations notify")
		return w.Destinations(ctx, func(peers []*pbs.ServerPeer) error {
			s.logger.Debug("updated destinations list", "peers", len(peers))

			if err := pb.Write(s.stream, &pbs.Response{
				Source: &pbs.Response_Source{
					Peers: peers,
				},
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

package control

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
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
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/nacl/secretbox"
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

		cc := &controlConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go cc.run(ctx)
	}
}

type controlConn struct {
	server *Server
	conn   quic.Connection
	logger *slog.Logger

	auth Authentication
	id   ksuid.KSUID
}

func (c *controlConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (c *controlConn) runErr(ctx context.Context) error {
	if auth, id, err := c.authenticate(ctx); err != nil {
		c.conn.CloseWithError(1, "auth failed")
		return kleverr.Ret(err)
	} else {
		c.auth = auth
		c.id = id
		c.logger = c.logger.With("client-id", id)
	}

	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			return err
		}

		cs := &controlStream{
			conn:   c,
			stream: stream,
		}
		go cs.run(ctx)
	}
}

var retAuth = kleverr.Ret2[Authentication, ksuid.KSUID]

func (c *controlConn) authenticate(ctx context.Context) (Authentication, ksuid.KSUID, error) {
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

	var id ksuid.KSUID
	if plain, err := c.decodeReconnect(req.Token, req.ReconnectToken); err != nil {
		c.logger.Debug("decode failed", "err", err)
		id = ksuid.New()
	} else if sid, err := ksuid.FromBytes(plain); err != nil {
		c.logger.Debug("decode failed", "err", err)
		id = ksuid.New()
	} else {
		id = sid
	}

	origin, err := pb.AddrPortFromNet(c.conn.RemoteAddr())
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "cannot resolve origin: %v", err)
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retAuth(err)
		}
		return retAuth(err)
	}

	retoken, err := c.encodeReconnect(req.Token, id.Bytes())
	if err != nil {
		c.logger.Debug("encrypting failed", "err", err)
		retoken = nil
	}
	if err := pb.Write(authStream, &pbs.AuthenticateResp{
		Public:         origin,
		ReconnectToken: retoken,
	}); err != nil {
		return retAuth(err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr())
	return auth, id, nil
}

func (c *controlConn) secretKey(token string) [32]byte {
	// TODO reevaluate this
	data := append([]byte(token), c.server.tlsConf.Certificates[0].Leaf.Raw...)
	return blake2s.Sum256(data)
}

func (c *controlConn) encodeReconnect(token string, id []byte) ([]byte, error) {
	secretKey := c.secretKey(token)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, kleverr.Newf("could not read rand: %w", err)
	}

	data := secretbox.Seal(nonce[:], id, &nonce, &secretKey)
	return data, nil
}

func (c *controlConn) decodeReconnect(token string, encrypted []byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, kleverr.New("missing encrypted data")
	}
	secretKey := c.secretKey(token)

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &secretKey)
	if !ok {
		return nil, kleverr.New("cannot open secretbox")
	}
	return decrypted, nil
}

type controlStream struct {
	conn   *controlConn
	stream quic.Stream
}

func (s *controlStream) run(ctx context.Context) {
	defer s.stream.Close()

	if err := s.runErr(ctx); err != nil {
		s.conn.logger.Warn("error while running", "err", err)
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
	if newFwd, err := s.conn.auth.ValidateDestination(fwd); err != nil {
		err := pb.NewError(pb.Error_RelayDestinationValidationFailed, "failed to validate desination '%s': %v", fwd, err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	} else {
		fwd = newFwd
	}

	clientCert, err := x509.ParseCertificate(req.ClientCertificate)
	if err != nil {
		err := pb.NewError(pb.Error_RelayInvalidCertificate, "invalid certificate: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	defer s.conn.logger.Debug("completed destination relay notify")
	return s.conn.server.relays.Destination(ctx, fwd, clientCert, func(relays map[model.HostPort]*x509.Certificate) error {
		s.conn.logger.Debug("updated destination relay list", "relays", len(relays))

		var addrs []*pbs.Relay
		for hp, cert := range relays {
			addrs = append(addrs, &pbs.Relay{
				Address:           hp.PB(),
				ServerCertificate: cert.Raw,
			})
		}

		if err := pb.Write(s.stream, &pbs.Response{
			Relay: &pbs.Response_Relays{
				Relays: addrs,
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
	if newFrom, err := s.conn.auth.ValidateDestination(from); err != nil {
		err := pb.NewError(pb.Error_DestinationValidationFailed, "failed to validte desination '%s': %v", from, err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	} else {
		from = newFrom
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
		defer s.conn.logger.Debug("completed sources notify")
		return w.Sources(ctx, func(peers []*pbs.ServerPeer) error {
			s.conn.logger.Debug("updated sources list", "peers", len(peers))

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
	if newFwd, err := s.conn.auth.ValidateSource(fwd); err != nil {
		err := pb.NewError(pb.Error_RelaySourceValidationFailed, "failed to validate source '%s': %v", fwd, err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	} else {
		fwd = newFwd
	}

	clientCert, err := x509.ParseCertificate(req.ClientCertificate)
	if err != nil {
		err := pb.NewError(pb.Error_RelayInvalidCertificate, "invalid certificate: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	defer s.conn.logger.Debug("completed source relay notify")
	return s.conn.server.relays.Source(ctx, fwd, clientCert, func(relays map[model.HostPort]*x509.Certificate) error {
		s.conn.logger.Debug("updated source relay list", "relays", len(relays))

		var addrs []*pbs.Relay
		for hp, cert := range relays {
			addrs = append(addrs, &pbs.Relay{
				Address:           hp.PB(),
				ServerCertificate: cert.Raw,
			})
		}

		if err := pb.Write(s.stream, &pbs.Response{
			Relay: &pbs.Response_Relays{
				Relays: addrs,
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
	if newTo, err := s.conn.auth.ValidateSource(to); err != nil {
		err := pb.NewError(pb.Error_SourceValidationFailed, "failed to validate source '%s': %v", to, err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	} else {
		to = newTo
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
		defer s.conn.logger.Debug("completed destinations notify")
		return w.Destinations(ctx, func(peers []*pbs.ServerPeer) error {
			s.conn.logger.Debug("updated destinations list", "peers", len(peers))

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
	s.conn.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(s.stream, &pbc.Response{Error: err})
}

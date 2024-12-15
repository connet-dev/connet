package control

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"io"
	"log/slog"

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

type ClientAuthenticator interface {
	Authenticate(token string) (ClientAuthentication, error)
}

type ClientAuthentication interface {
	ValidateDestination(dst model.Forward) (model.Forward, error)
	ValidateSource(src model.Forward) (model.Forward, error)
}

type ClientRelays interface {
	Destination(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
		notify func(map[model.HostPort]*x509.Certificate) error) error
	Source(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
		notify func(map[model.HostPort]*x509.Certificate) error) error
}

type clientServer struct {
	auth      ClientAuthenticator
	relays    ClientRelays
	encode    []byte
	whisperer *whisperer
	logger    *slog.Logger
}

func (s *clientServer) handle(ctx context.Context, conn quic.Connection) error {
	cc := &clientConn{
		server: s,
		conn:   conn,
		logger: s.logger,
	}
	go cc.run(ctx)
	return nil
}

type clientConn struct {
	server *clientServer
	conn   quic.Connection
	logger *slog.Logger

	auth ClientAuthentication
	id   ksuid.KSUID
}

func (c *clientConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (c *clientConn) runErr(ctx context.Context) error {
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

		cs := &clientStream{
			conn:   c,
			stream: stream,
		}
		go cs.run(ctx)
	}
}

var retClientAuth = kleverr.Ret2[ClientAuthentication, ksuid.KSUID]

func (c *clientConn) authenticate(ctx context.Context) (ClientAuthentication, ksuid.KSUID, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return retClientAuth(err)
	}
	defer authStream.Close()

	req := &pbs.Authenticate{}
	if err := pb.Read(authStream, req); err != nil {
		return retClientAuth(err)
	}

	auth, err := c.server.auth.Authenticate(req.Token)
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "Invalid or unknown token")
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retClientAuth(err)
		}
		return retClientAuth(err)
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
			return retClientAuth(err)
		}
		return retClientAuth(err)
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
		return retClientAuth(err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr())
	return auth, id, nil
}

func (c *clientConn) secretKey(token string) [32]byte {
	// TODO reevaluate this
	data := append([]byte(token), c.server.encode...)
	return blake2s.Sum256(data)
}

func (c *clientConn) encodeReconnect(token string, id []byte) ([]byte, error) {
	secretKey := c.secretKey(token)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, kleverr.Newf("could not read rand: %w", err)
	}

	data := secretbox.Seal(nonce[:], id, &nonce, &secretKey)
	return data, nil
}

func (c *clientConn) decodeReconnect(token string, encrypted []byte) ([]byte, error) {
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

type clientStream struct {
	conn   *clientConn
	stream quic.Stream
}

func (s *clientStream) run(ctx context.Context) {
	defer s.stream.Close()

	if err := s.runErr(ctx); err != nil {
		s.conn.logger.Warn("error while running", "err", err)
	}
}

func (s *clientStream) runErr(ctx context.Context) error {
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

func (s *clientStream) destinationRelay(ctx context.Context, req *pbs.Request_DestinationRelay) error {
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

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		connCtx := s.conn.conn.Context()
		<-connCtx.Done()
		return context.Cause(connCtx)
	})

	g.Go(func() error {
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
	})

	return g.Wait()
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

func (s *clientStream) destination(ctx context.Context, req *pbs.Request_Destination) error {
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

	s.conn.server.whisperer.AddDestination(from, s.conn.id, req.Peer)
	defer s.conn.server.whisperer.RemoveDestination(from, s.conn.id)

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

			s.conn.server.whisperer.AddDestination(from, s.conn.id, req.Destination.Peer)
		}
	})

	g.Go(func() error {
		defer s.conn.logger.Debug("completed sources notify")
		return s.conn.server.whisperer.Sources(ctx, from, func(peers []*pbs.ServerPeer) error {
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

func (s *clientStream) sourceRelay(ctx context.Context, req *pbs.Request_SourceRelay) error {
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

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		connCtx := s.conn.conn.Context()
		<-connCtx.Done()
		return context.Cause(connCtx)
	})

	g.Go(func() error {
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
	})

	return g.Wait()
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

func (s *clientStream) source(ctx context.Context, req *pbs.Request_Source) error {
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

	s.conn.server.whisperer.AddSource(to, s.conn.id, req.Peer)
	defer s.conn.server.whisperer.RemoveSource(to, s.conn.id)

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

			s.conn.server.whisperer.AddSource(to, s.conn.id, req.Source.Peer)
		}
	})

	g.Go(func() error {
		defer s.conn.logger.Debug("completed destinations notify")
		return s.conn.server.whisperer.Destinations(ctx, to, func(peers []*pbs.ServerPeer) error {
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

func (s *clientStream) unknown(ctx context.Context, req *pbs.Request) error {
	s.conn.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(s.stream, &pbc.Response{Error: err})
}

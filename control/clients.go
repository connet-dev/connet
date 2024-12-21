package control

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"

	"github.com/keihaya-com/connet/logc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/sync/errgroup"
)

type ClientAuthenticator interface {
	Authenticate(token string) (ClientAuthentication, error)
}

type ClientAuthentication interface {
	Validate(fwd model.Forward, role model.Role) (model.Forward, error)
}

type ClientRelays interface {
	Client(ctx context.Context, fwd model.Forward, role model.Role, cert *x509.Certificate,
		notify func(map[model.HostPort]*x509.Certificate) error) error
}

func newClientServer(
	auth ClientAuthenticator,
	relays ClientRelays,
	config logc.KV[configKey, configValue],
	dir string,
	logger *slog.Logger,
) (*clientServer, error) {
	clients, err := logc.NewKV[clientKey, clientValue](filepath.Join(dir, "clients"))
	if err != nil {
		return nil, err
	}

	clientsMsgs, clientsOffset, err := clients.Snapshot()
	if err != nil {
		return nil, err
	}

	clientsCache := map[cacheKey][]*pbs.ServerPeer{}
	for _, msg := range clientsMsgs {
		key := cacheKey{msg.Key.Forward, msg.Key.Role}
		clientsCache[key] = append(clientsCache[key], &pbs.ServerPeer{
			Id:     msg.Key.ID.String(),
			Direct: msg.Value.Peer.Direct,
			Relays: msg.Value.Peer.Relays,
		})
	}

	serverClientSecret, err := config.GetOrInit(configServerClientSecret, func(ck configKey) (configValue, error) {
		privateKey := [32]byte{}
		if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
			return configValue{}, err
		}
		return configValue{Bytes: privateKey[:]}, nil
	})

	s := &clientServer{
		auth:   auth,
		relays: relays,
		logger: logger.With("server", "clients"),

		clientSecretKey: [32]byte(serverClientSecret.Bytes),
		clients:         clients,

		clientsCache:  clientsCache,
		clientsOffset: clientsOffset,
	}

	return s, nil
}

type clientServer struct {
	auth   ClientAuthenticator
	relays ClientRelays
	encode []byte
	logger *slog.Logger

	clientSecretKey [32]byte
	clients         logc.KV[clientKey, clientValue]

	clientsCache  map[cacheKey][]*pbs.ServerPeer
	clientsOffset int64
	clientsMu     sync.RWMutex
}

func (s *clientServer) put(fwd model.Forward, role model.Role, id ksuid.KSUID, peer *pbs.ClientPeer) error {
	return s.clients.Put(clientKey{fwd, role, id}, clientValue{peer})
}

func (s *clientServer) del(fwd model.Forward, role model.Role, id ksuid.KSUID) error {
	return s.clients.Del(clientKey{fwd, role, id})
}

func (s *clientServer) get(fwd model.Forward, role model.Role) ([]*pbs.ServerPeer, int64) {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	return s.clientsCache[cacheKey{fwd, role}], s.clientsOffset
}

func (s *clientServer) listen(ctx context.Context, fwd model.Forward, role model.Role, notify func(peers []*pbs.ServerPeer) error) error {
	peers, offset := s.get(fwd, role)
	if len(peers) > 0 {
		if err := notify(peers); err != nil {
			return err
		}
	}

	for {
		msgs, nextOffset, err := s.clients.Consume(ctx, offset)
		if err != nil {
			return err
		}

		var changed bool
		for _, msg := range msgs {
			if msg.Key.Forward != fwd || msg.Key.Role != role {
				continue
			}

			if msg.Delete {
				peers = slices.DeleteFunc(peers, func(peer *pbs.ServerPeer) bool {
					return peer.Id == msg.Key.ID.String()
				})
			} else {
				peer := &pbs.ServerPeer{
					Id:     msg.Key.ID.String(),
					Direct: msg.Value.Peer.Direct,
					Relays: msg.Value.Peer.Relays,
				}
				idx := slices.IndexFunc(peers, func(peer *pbs.ServerPeer) bool { return peer.Id == msg.Key.ID.String() })
				if idx >= 0 {
					peers[idx] = peer
				} else {
					peers = append(peers, peer)
				}
			}
			changed = true
		}

		offset = nextOffset

		if changed {
			if err := notify(peers); err != nil {
				return err
			}
		}
	}
}

func (s *clientServer) run(ctx context.Context) error {
	update := func(msg logc.Message[clientKey, clientValue]) error {
		s.clientsMu.Lock()
		defer s.clientsMu.Unlock()

		key := cacheKey{msg.Key.Forward, msg.Key.Role}
		peers := s.clientsCache[key]
		if msg.Delete {
			peers = slices.DeleteFunc(peers, func(peer *pbs.ServerPeer) bool {
				return peer.Id == msg.Key.ID.String()
			})
			if len(peers) == 0 {
				delete(s.clientsCache, key)
			} else {
				s.clientsCache[key] = peers
			}
		} else {
			peer := &pbs.ServerPeer{
				Id:     msg.Key.ID.String(),
				Direct: msg.Value.Peer.Direct,
				Relays: msg.Value.Peer.Relays,
			}
			idx := slices.IndexFunc(peers, func(peer *pbs.ServerPeer) bool { return peer.Id == msg.Key.ID.String() })
			if idx >= 0 {
				peers[idx] = peer
			} else {
				peers = append(peers, peer)
			}
			s.clientsCache[key] = peers
		}

		s.clientsOffset = msg.Offset + 1
		return nil
	}

	for {
		s.clientsMu.RLock()
		offset := s.clientsOffset
		s.clientsMu.RUnlock()

		msgs, nextOffset, err := s.clients.Consume(ctx, offset)
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			if err := update(msg); err != nil {
				return err
			}
		}

		s.clientsMu.Lock()
		s.clientsOffset = nextOffset
		s.clientsMu.Unlock()
	}
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
		if perr := pb.GetError(err); perr != nil {
			c.conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
		} else {
			c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "Error while authenticating")
		}
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
	if plain, err := c.decodeReconnect(req.ReconnectToken); err != nil {
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

	retoken, err := c.encodeReconnect(id.Bytes())
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

func (c *clientConn) encodeReconnect(id []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, kleverr.Newf("could not read rand: %w", err)
	}

	data := secretbox.Seal(nonce[:], id, &nonce, &c.server.clientSecretKey)
	return data, nil
}

func (c *clientConn) decodeReconnect(encrypted []byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, kleverr.New("missing encrypted data")
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &c.server.clientSecretKey)
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
	case req.Announce != nil:
		return s.announce(ctx, req.Announce)
	case req.Relay != nil:
		return s.relay(ctx, req.Relay)
	default:
		return s.unknown(ctx, req)
	}
}

func validatePeerCert(fwd model.Forward, peer *pbs.ClientPeer) *pb.Error {
	if peer.Direct == nil {
		return nil
	}
	if _, err := x509.ParseCertificate(peer.Direct.ClientCertificate); err != nil {
		return pb.NewError(pb.Error_AnnounceInvalidClientCertificate, "'%s' client cert is invalid", fwd)
	}
	if _, err := x509.ParseCertificate(peer.Direct.ServerCertificate); err != nil {
		return pb.NewError(pb.Error_AnnounceInvalidServerCertificate, "'%s' server cert is invalid", fwd)
	}
	return nil
}

func (s *clientStream) announce(ctx context.Context, req *pbs.Request_Announce) error {
	fwd := model.ForwardFromPB(req.Forward)
	role := model.RoleFromPB(req.Role)
	if newFwd, err := s.conn.auth.Validate(fwd, role); err != nil {
		err := pb.NewError(pb.Error_AnnounceValidationFailed, "failed to validte desination '%s': %v", fwd, err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	} else {
		fwd = newFwd
	}

	if err := validatePeerCert(fwd, req.Peer); err != nil {
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	if err := s.conn.server.put(fwd, role, s.conn.id, req.Peer); err != nil {
		return err
	}
	defer s.conn.server.del(fwd, role, s.conn.id)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			req, err := pbs.ReadRequest(s.stream)
			if err != nil {
				return err
			}
			if req.Announce == nil {
				respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
				if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			if err := validatePeerCert(fwd, req.Announce.Peer); err != nil {
				if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
					return kleverr.Newf("could not write error response: %w", err)
				}
				return err
			}

			if err := s.conn.server.put(fwd, role, s.conn.id, req.Announce.Peer); err != nil {
				return err
			}
		}
	})

	g.Go(func() error {
		defer s.conn.logger.Debug("completed sources notify")
		return s.conn.server.listen(ctx, fwd, role.Invert(), func(peers []*pbs.ServerPeer) error {
			s.conn.logger.Debug("updated sources list", "peers", len(peers))

			if err := pb.Write(s.stream, &pbs.Response{
				Announce: &pbs.Response_Announce{
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

func (s *clientStream) relay(ctx context.Context, req *pbs.Request_Relay) error {
	fwd := model.ForwardFromPB(req.Forward)
	role := model.RoleFromPB(req.Role)
	if newFwd, err := s.conn.auth.Validate(fwd, role); err != nil {
		err := pb.NewError(pb.Error_RelayValidationFailed, "failed to validate desination '%s': %v", fwd, err)
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
		defer s.conn.logger.Debug("completed relay notify")
		return s.conn.server.relays.Client(ctx, fwd, role, clientCert, func(relays map[model.HostPort]*x509.Certificate) error {
			s.conn.logger.Debug("updated relay list", "relays", len(relays))

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

func (s *clientStream) unknown(ctx context.Context, req *pbs.Request) error {
	s.conn.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(s.stream, &pbc.Response{Error: err})
}

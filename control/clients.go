package control

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"

	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	"github.com/connet-dev/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/sync/errgroup"
)

type ClientAuthenticator interface {
	Authenticate(token string, addr net.Addr) (ClientAuthentication, error)
}

type ClientAuthentication interface {
	Validate(fwd model.Forward, role model.Role) (model.Forward, error)

	encoding.BinaryMarshaler
}

type ClientRelays interface {
	Client(ctx context.Context, fwd model.Forward, role model.Role, cert *x509.Certificate,
		notify func(map[ksuid.KSUID]relayCacheValue) error) error
}

func newClientServer(
	auth ClientAuthenticator,
	restr netc.IPRestriction,
	relays ClientRelays,
	config logc.KV[ConfigKey, ConfigValue],
	stores Stores,
	logger *slog.Logger,
) (*clientServer, error) {
	conns, err := stores.ClientConns()
	if err != nil {
		return nil, err
	}

	peers, err := stores.ClientPeers()
	if err != nil {
		return nil, err
	}

	clientsMsgs, clientsOffset, err := peers.Snapshot()
	if err != nil {
		return nil, err
	}

	peersCache := map[cacheKey][]*pbs.ServerPeer{}
	for _, msg := range clientsMsgs {
		key := cacheKey{msg.Key.Forward, msg.Key.Role}
		peersCache[key] = append(peersCache[key], &pbs.ServerPeer{
			Id:     msg.Key.ID.String(),
			Direct: msg.Value.Peer.Direct,
			Relays: msg.Value.Peer.Relays,
		})
	}

	serverSecret, err := config.GetOrInit(configServerClientSecret, func(ck ConfigKey) (ConfigValue, error) {
		privateKey := [32]byte{}
		if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
			return ConfigValue{}, err
		}
		return ConfigValue{Bytes: privateKey[:]}, nil
	})
	if err != nil {
		return nil, err
	}

	s := &clientServer{
		auth:   auth,
		restr:  restr,
		relays: relays,
		logger: logger.With("server", "clients"),

		clientSecretKey: [32]byte(serverSecret.Bytes),

		conns: conns,
		peers: peers,

		peersCache:  peersCache,
		peersOffset: clientsOffset,
	}

	return s, nil
}

type clientServer struct {
	auth   ClientAuthenticator
	restr  netc.IPRestriction
	relays ClientRelays
	encode []byte
	logger *slog.Logger

	clientSecretKey [32]byte

	conns logc.KV[ClientConnKey, ClientConnValue]
	peers logc.KV[ClientPeerKey, ClientPeerValue]

	peersCache  map[cacheKey][]*pbs.ServerPeer
	peersOffset int64
	peersMu     sync.RWMutex
}

func (s *clientServer) connected(id ksuid.KSUID, auth ClientAuthentication, remote net.Addr) error {
	authData, err := auth.MarshalBinary()
	if err != nil {
		return err
	}
	return s.conns.Put(ClientConnKey{id}, ClientConnValue{Authentication: authData, Addr: remote.String()})
}

func (s *clientServer) disconnected(id ksuid.KSUID) error {
	return s.conns.Del(ClientConnKey{id})
}

func (s *clientServer) announce(fwd model.Forward, role model.Role, id ksuid.KSUID, peer *pbs.ClientPeer) error {
	return s.peers.Put(ClientPeerKey{fwd, role, id}, ClientPeerValue{peer})
}

func (s *clientServer) revoke(fwd model.Forward, role model.Role, id ksuid.KSUID) error {
	return s.peers.Del(ClientPeerKey{fwd, role, id})
}

func (s *clientServer) announcements(fwd model.Forward, role model.Role) ([]*pbs.ServerPeer, int64) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()

	return slices.Clone(s.peersCache[cacheKey{fwd, role}]), s.peersOffset
}

func (s *clientServer) listen(ctx context.Context, fwd model.Forward, role model.Role, notify func(peers []*pbs.ServerPeer) error) error {
	peers, offset := s.announcements(fwd, role)
	if len(peers) > 0 {
		if err := notify(peers); err != nil {
			return err
		}
	}

	for {
		msgs, nextOffset, err := s.peers.Consume(ctx, offset)
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
				npeer := &pbs.ServerPeer{
					Id:     msg.Key.ID.String(),
					Direct: msg.Value.Peer.Direct,
					Relays: msg.Value.Peer.Relays,
				}
				idx := slices.IndexFunc(peers, func(peer *pbs.ServerPeer) bool { return peer.Id == msg.Key.ID.String() })
				if idx >= 0 {
					peers[idx] = npeer
				} else {
					peers = append(peers, npeer)
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
	update := func(msg logc.Message[ClientPeerKey, ClientPeerValue]) error {
		s.peersMu.Lock()
		defer s.peersMu.Unlock()

		key := cacheKey{msg.Key.Forward, msg.Key.Role}
		peers := s.peersCache[key]
		if msg.Delete {
			peers = slices.DeleteFunc(peers, func(peer *pbs.ServerPeer) bool {
				return peer.Id == msg.Key.ID.String()
			})
			if len(peers) == 0 {
				delete(s.peersCache, key)
			} else {
				s.peersCache[key] = peers
			}
		} else {
			npeer := &pbs.ServerPeer{
				Id:     msg.Key.ID.String(),
				Direct: msg.Value.Peer.Direct,
				Relays: msg.Value.Peer.Relays,
			}
			idx := slices.IndexFunc(peers, func(peer *pbs.ServerPeer) bool { return peer.Id == msg.Key.ID.String() })
			if idx >= 0 {
				peers[idx] = npeer
			} else {
				peers = append(peers, npeer)
			}
			s.peersCache[key] = peers
		}

		s.peersOffset = msg.Offset + 1
		return nil
	}

	for {
		s.peersMu.RLock()
		offset := s.peersOffset
		s.peersMu.RUnlock()

		msgs, nextOffset, err := s.peers.Consume(ctx, offset)
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			if err := update(msg); err != nil {
				return err
			}
		}

		s.peersMu.Lock()
		s.peersOffset = nextOffset
		s.peersMu.Unlock()
	}
}

func (s *clientServer) handle(ctx context.Context, conn quic.Connection) {
	if s.restr.AcceptAddr(conn.RemoteAddr()) {
		cc := &clientConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go cc.run(ctx)
	} else {
		conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "not allowed")
	}
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
		c.logger.Debug("error while running", "err", err)
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

	if err := c.server.connected(c.id, c.auth, c.conn.RemoteAddr()); err != nil {
		return err
	}
	defer c.server.disconnected(c.id)

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

	auth, err := c.server.auth.Authenticate(req.Token, c.conn.RemoteAddr())
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
		s.conn.logger.Debug("error while running", "err", err)
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
		err := pb.NewError(pb.Error_AnnounceValidationFailed, "failed to validate forward '%s': %v", fwd, err)
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

	if err := s.conn.server.announce(fwd, role, s.conn.id, req.Peer); err != nil {
		return err
	}
	defer s.conn.server.revoke(fwd, role, s.conn.id)

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

			if err := s.conn.server.announce(fwd, role, s.conn.id, req.Announce.Peer); err != nil {
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
		return s.conn.server.relays.Client(ctx, fwd, role, clientCert, func(relays map[ksuid.KSUID]relayCacheValue) error {
			s.conn.logger.Debug("updated relay list", "relays", len(relays))

			var addrs []*pbs.Relay
			for _, value := range relays {
				addrs = append(addrs, &pbs.Relay{
					Address:           value.Hostport.PB(),
					ServerCertificate: value.Cert.Raw,
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

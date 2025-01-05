package control

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbr"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/sync/errgroup"
)

type RelayAuthenticator interface {
	Authenticate(token string, addr net.Addr) (RelayAuthentication, error)
}

type RelayAuthentication interface {
	Allow(fwd model.Forward) bool

	encoding.BinaryMarshaler
}

func newRelayServer(
	auth RelayAuthenticator,
	restr netc.IPRestriction,
	config logc.KV[ConfigKey, ConfigValue],
	stores Stores,
	logger *slog.Logger,
) (*relayServer, error) {
	conns, err := stores.RelayConns()
	if err != nil {
		return nil, err
	}

	clients, err := stores.RelayClients()
	if err != nil {
		return nil, err
	}

	servers, err := stores.RelayServers()
	if err != nil {
		return nil, err
	}

	serverOffsets, err := stores.RelayServerOffsets()
	if err != nil {
		return nil, err
	}

	forwardsMsgs, forwardsOffset, err := servers.Snapshot()
	if err != nil {
		return nil, err
	}

	forwardsCache := map[model.Forward]map[ksuid.KSUID]relayCacheValue{}
	for _, msg := range forwardsMsgs {
		srv := forwardsCache[msg.Key.Forward]
		if srv == nil {
			srv = map[ksuid.KSUID]relayCacheValue{}
			forwardsCache[msg.Key.Forward] = srv
		}
		srv[msg.Key.RelayID] = relayCacheValue{Hostport: msg.Value.Hostport, Cert: msg.Value.Cert}
	}

	serverIDConfig, err := config.GetOrInit(configServerID, func(ck ConfigKey) (ConfigValue, error) {
		return ConfigValue{String: model.GenServerName("connet")}, nil
	})
	if err != nil {
		return nil, err
	}

	serverSecret, err := config.GetOrInit(configServerRelaySecret, func(ck ConfigKey) (ConfigValue, error) {
		privateKey := [32]byte{}
		if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
			return ConfigValue{}, err
		}
		return ConfigValue{Bytes: privateKey[:]}, nil
	})
	if err != nil {
		return nil, err
	}

	return &relayServer{
		id:     serverIDConfig.String,
		auth:   auth,
		restr:  restr,
		logger: logger.With("server", "relays"),

		relaySecretKey: [32]byte(serverSecret.Bytes),

		stores:        stores,
		conns:         conns,
		clients:       clients,
		servers:       servers,
		serverOffsets: serverOffsets,

		forwardsCache:  forwardsCache,
		forwardsOffset: forwardsOffset,
	}, nil
}

type relayServer struct {
	id     string
	auth   RelayAuthenticator
	restr  netc.IPRestriction
	logger *slog.Logger

	relaySecretKey [32]byte

	stores        Stores
	conns         logc.KV[RelayConnKey, RelayConnValue]
	clients       logc.KV[RelayClientKey, RelayClientValue]
	servers       logc.KV[RelayServerKey, RelayServerValue]
	serverOffsets logc.KV[RelayConnKey, int64]

	forwardsCache  map[model.Forward]map[ksuid.KSUID]relayCacheValue
	forwardsOffset int64
	forwardsMu     sync.RWMutex
}

func (s *relayServer) getForward(fwd model.Forward) (map[ksuid.KSUID]relayCacheValue, int64) {
	s.forwardsMu.RLock()
	defer s.forwardsMu.RUnlock()

	return maps.Clone(s.forwardsCache[fwd]), s.forwardsOffset
}

func (s *relayServer) Client(ctx context.Context, fwd model.Forward, role model.Role, cert *x509.Certificate,
	notifyFn func(map[ksuid.KSUID]relayCacheValue) error) error {

	key := RelayClientKey{Forward: fwd, Role: role, Key: certc.NewKey(cert)}
	val := RelayClientValue{Cert: cert}
	s.clients.Put(key, val)
	defer s.clients.Del(key)

	return s.listen(ctx, fwd, notifyFn)
}

func (s *relayServer) listen(ctx context.Context, fwd model.Forward,
	notifyFn func(map[ksuid.KSUID]relayCacheValue) error) error {

	servers, offset := s.getForward(fwd)
	if len(servers) > 0 {
		if err := notifyFn(servers); err != nil {
			return err
		}
	}

	for {
		msgs, nextOffset, err := s.servers.Consume(ctx, offset)
		if err != nil {
			return err
		}

		var changed bool
		for _, msg := range msgs {
			if msg.Key.Forward != fwd {
				continue
			}

			if msg.Delete {
				delete(servers, msg.Key.RelayID)
			} else {
				if servers == nil {
					servers = map[ksuid.KSUID]relayCacheValue{}
				}
				servers[msg.Key.RelayID] = relayCacheValue{Hostport: msg.Value.Hostport, Cert: msg.Value.Cert}
			}
			changed = true
		}

		offset = nextOffset

		if changed {
			if err := notifyFn(servers); err != nil {
				return err
			}
		}
	}
}

func (s *relayServer) run(ctx context.Context) error {
	update := func(msg logc.Message[RelayServerKey, RelayServerValue]) error {
		s.forwardsMu.Lock()
		defer s.forwardsMu.Unlock()

		srv := s.forwardsCache[msg.Key.Forward]
		if msg.Delete {
			delete(srv, msg.Key.RelayID)
			if len(srv) == 0 {
				delete(s.forwardsCache, msg.Key.Forward)
			}
		} else {
			if srv == nil {
				srv = map[ksuid.KSUID]relayCacheValue{}
				s.forwardsCache[msg.Key.Forward] = srv
			}
			srv[msg.Key.RelayID] = relayCacheValue{Hostport: msg.Value.Hostport, Cert: msg.Value.Cert}
		}

		s.forwardsOffset = msg.Offset + 1
		return nil
	}

	for {
		s.forwardsMu.RLock()
		offset := s.forwardsOffset
		s.forwardsMu.RUnlock()

		msgs, nextOffset, err := s.servers.Consume(ctx, offset)
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			if err := update(msg); err != nil {
				return err
			}
		}

		s.forwardsMu.Lock()
		s.forwardsOffset = nextOffset
		s.forwardsMu.Unlock()
	}
}

func (s *relayServer) handle(ctx context.Context, conn quic.Connection) {
	if s.restr.AcceptAddr(conn.RemoteAddr()) {
		rc := &relayConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go rc.run(ctx)
	} else {
		conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "not allowed")
	}
}

func (s *relayServer) getRelayServerOffset(id ksuid.KSUID) (int64, error) {
	offset, err := s.serverOffsets.Get(RelayConnKey{id})
	switch {
	case errors.Is(err, logc.ErrNotFound):
		return logc.OffsetOldest, nil
	case err != nil:
		return logc.OffsetInvalid, err
	default:
		return offset, nil
	}
}

func (s *relayServer) setRelayServerOffset(id ksuid.KSUID, offset int64) error {
	return s.serverOffsets.Put(RelayConnKey{id}, offset)
}

type relayConn struct {
	server *relayServer
	conn   quic.Connection
	logger *slog.Logger

	forwards logc.KV[RelayForwardKey, RelayForwardValue]
	id       ksuid.KSUID
	auth     RelayAuthentication
	hostport model.HostPort
}

func (c *relayConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running", "err", err)
	}
}

func (c *relayConn) runErr(ctx context.Context) error {
	if auth, id, hp, err := c.authenticate(ctx); err != nil {
		if perr := pb.GetError(err); perr != nil {
			c.conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
		} else {
			c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "Error while authenticating")
		}
		return kleverr.Ret(err)
	} else {
		c.id = id
		c.auth = auth
		c.hostport = hp
		c.logger = c.logger.With("relay", hp)
	}

	forwards, err := c.server.stores.RelayForwards(c.id)
	if err != nil {
		return err
	}
	defer forwards.Close()
	c.forwards = forwards

	key := RelayConnKey{ID: c.id}
	authData, err := c.auth.MarshalBinary()
	if err != nil {
		return err
	}
	value := RelayConnValue{Authentication: authData, Hostport: c.hostport}
	if err := c.server.conns.Put(key, value); err != nil {
		return err
	}
	defer c.server.conns.Del(key)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return c.runRelayClients(ctx) })
	g.Go(func() error { return c.runRelayForwards(ctx) })
	g.Go(func() error { return c.runRelayServers(ctx) })

	return g.Wait()
}

var retRelayAuth = kleverr.Ret3[RelayAuthentication, ksuid.KSUID, model.HostPort]

func (c *relayConn) authenticate(ctx context.Context) (RelayAuthentication, ksuid.KSUID, model.HostPort, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return retRelayAuth(err)
	}
	defer authStream.Close()

	req := &pbr.AuthenticateReq{}
	if err := pb.Read(authStream, req); err != nil {
		return retRelayAuth(err)
	}

	auth, err := c.server.auth.Authenticate(req.Token, c.conn.RemoteAddr())
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "Invalid or unknown token")
		if err := pb.Write(authStream, &pbr.AuthenticateResp{Error: err}); err != nil {
			return retRelayAuth(err)
		}
		return retRelayAuth(err)
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

	retoken, err := c.encodeReconnect(id.Bytes())
	if err != nil {
		c.logger.Debug("encrypting failed", "err", err)
		retoken = nil
	}
	if err := pb.Write(authStream, &pbr.AuthenticateResp{
		ControlId:      c.server.id,
		ReconnectToken: retoken,
	}); err != nil {
		return retRelayAuth(err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr())
	return auth, id, model.HostPortFromPB(req.Addr), nil
}

func (c *relayConn) encodeReconnect(id []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, kleverr.Newf("could not read rand: %w", err)
	}

	data := secretbox.Seal(nonce[:], id, &nonce, &c.server.relaySecretKey)
	return data, nil
}

func (c *relayConn) decodeReconnect(encrypted []byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, kleverr.New("missing encrypted data")
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &c.server.relaySecretKey)
	if !ok {
		return nil, kleverr.New("cannot open secretbox")
	}
	return decrypted, nil
}

func (c *relayConn) runRelayClients(ctx context.Context) error {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		req := &pbr.ClientsReq{}
		if err := pb.Read(stream, req); err != nil {
			return err
		}

		var msgs []logc.Message[RelayClientKey, RelayClientValue]
		var nextOffset int64
		if req.Offset == logc.OffsetOldest {
			msgs, nextOffset, err = c.server.clients.Snapshot()
			c.logger.Debug("sending initial relay changes", "offset", nextOffset, "changes", len(msgs))
		} else {
			msgs, nextOffset, err = c.server.clients.Consume(ctx, req.Offset)
			c.logger.Debug("sending delta relay changes", "offset", nextOffset, "changes", len(msgs))
		}
		if err != nil {
			return err
		}

		// if len(msgs) == 0 && offset >= 0 && offset < nextOffset {
		// TODO we are too far off and potentially have missed messages
		// }

		resp := &pbr.ClientsResp{Offset: nextOffset}

		for _, msg := range msgs {
			if !c.auth.Allow(msg.Key.Forward) {
				continue
			}

			change := &pbr.ClientsResp_Change{
				Forward:        msg.Key.Forward.PB(),
				Role:           msg.Key.Role.PB(),
				CertificateKey: msg.Key.Key.String(),
			}

			if msg.Delete {
				change.Change = pbr.ChangeType_ChangeDel
			} else {
				change.Change = pbr.ChangeType_ChangePut
				change.Certificate = msg.Value.Cert.Raw
			}

			resp.Changes = append(resp.Changes, change)
		}

		if err := pb.Write(stream, resp); err != nil {
			return err
		}
	}
}

func (c *relayConn) runRelayServers(ctx context.Context) error {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		offset, err := c.server.getRelayServerOffset(c.id)
		if err != nil {
			return err
		}

		req := &pbr.ServersReq{
			Offset: offset,
		}
		if err := pb.Write(stream, req); err != nil {
			return err
		}

		resp := &pbr.ServersResp{}
		if err := pb.Read(stream, resp); err != nil {
			return err
		}

		for _, change := range resp.Changes {
			key := RelayForwardKey{Forward: model.ForwardFromPB(change.Forward)}

			switch change.Change {
			case pbr.ChangeType_ChangePut:
				cert, err := x509.ParseCertificate(change.ServerCertificate)
				if err != nil {
					return err
				}
				value := RelayForwardValue{Cert: cert}
				if err := c.forwards.Put(key, value); err != nil {
					return err
				}
			case pbr.ChangeType_ChangeDel:
				if err := c.forwards.Del(key); err != nil {
					return err
				}
			default:
				return kleverr.New("unknown change")
			}
		}

		if err := c.server.setRelayServerOffset(c.id, resp.Offset); err != nil {
			return err
		}
	}
}

func (c *relayConn) runRelayForwards(ctx context.Context) error {
	initialMsgs, offset, err := c.forwards.Snapshot()
	if err != nil {
		return err
	}

	for _, msg := range initialMsgs {
		key := RelayServerKey{Forward: msg.Key.Forward, RelayID: c.id}
		value := RelayServerValue{Hostport: c.hostport, Cert: msg.Value.Cert}
		if err := c.server.servers.Put(key, value); err != nil {
			return err
		}
	}

	defer func() {
		msgs, _, err := c.forwards.Snapshot()
		if err != nil {
			c.logger.Warn("cannot snapshot forward", "err", err)
			return
		}

		for _, msg := range msgs {
			key := RelayServerKey{Forward: msg.Key.Forward, RelayID: c.id}
			if err := c.server.servers.Del(key); err != nil {
				c.logger.Warn("cannot delete forward", "key", key, "err", err)
			}
		}
	}()

	for {
		msgs, nextOffset, err := c.forwards.Consume(ctx, offset)
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			key := RelayServerKey{Forward: msg.Key.Forward, RelayID: c.id}
			if msg.Delete {
				if err := c.server.servers.Del(key); err != nil {
					return err
				}
			} else {
				value := RelayServerValue{Hostport: c.hostport, Cert: msg.Value.Cert}
				if err := c.server.servers.Put(key, value); err != nil {
					return err
				}
			}
		}

		offset = nextOffset
	}
}

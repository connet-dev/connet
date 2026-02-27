package control

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/logc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/proto/pbmodel"
	"github.com/quic-go/quic-go"
)

type ClientAuthenticateRequest struct {
	Proto        model.ClientControlNextProto
	Token        string
	Addr         net.Addr
	BuildVersion string
}

type ClientAuthenticator interface {
	Authenticate(req ClientAuthenticateRequest) (ClientAuthentication, error)
	Validate(auth ClientAuthentication, endpoint model.Endpoint, role model.Role) (model.Endpoint, error)
}

type ClientAuthentication []byte

type ClientRelays interface {
	Relays(ctx context.Context, endpoint model.Endpoint, role model.Role, cert *x509.Certificate, auth ClientAuthentication,
		notify func(map[RelayID]*pbclient.Relay) error) error
}

func newClientServer(
	ingresses []Ingress,
	auth ClientAuthenticator,
	relays ClientRelays,
	config logc.KV[ConfigKey, ConfigValue],
	stores Stores,
	endpointExpiry time.Duration,
	logger *slog.Logger,
) (*clientServer, error) {
	conns, err := stores.ClientConns()
	if err != nil {
		return nil, fmt.Errorf("client conns store open: %w", err)
	}

	peers, err := stores.ClientPeers()
	if err != nil {
		return nil, fmt.Errorf("client peers store open: %w", err)
	}

	connsMsgs, _, err := conns.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("client snapshot: %w", err)
	}

	// delete stale conn entries
	for _, msg := range connsMsgs {
		if err := conns.Del(msg.Key); err != nil {
			return nil, fmt.Errorf("delete stale conn: %w", err)
		}
	}

	peersMsgs, peersOffset, err := peers.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("client peers snapshot: %w", err)
	}

	peersCache := map[peerKey][]peerValue{}
	for _, msg := range peersMsgs {
		if endpointExpiry == 0 {
			// Expiry disabled — delete stale peers immediately
			if err := peers.Del(msg.Key); err != nil {
				return nil, fmt.Errorf("delete stale peer: %w", err)
			}
			continue
		}

		// Add ALL peers to cache (they remain visible during grace period)
		key := peerKey{msg.Key.Endpoint, msg.Key.Role}
		peersCache[key] = append(peersCache[key], peerValue{msg.Key.ConnID, &pbclient.RemotePeer{
			Id:       msg.Key.ID.string,
			Metadata: msg.Value.Metadata,
			Peer:     msg.Value.Peer,
		}})

		// Mark as expired if not already
		if msg.Value.ExpiredAt == nil {
			now := time.Now()
			msg.Value.ExpiredAt = &now
			if err := peers.Put(msg.Key, msg.Value); err != nil {
				return nil, fmt.Errorf("expire stale peer: %w", err)
			}
		}
	}

	serverSecret, err := config.GetOrInit(configServerClientSecret, func(_ ConfigKey) (ConfigValue, error) {
		privateKey := [32]byte{}
		if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
			return ConfigValue{}, fmt.Errorf("generate rand: %w", err)
		}
		return ConfigValue{Bytes: privateKey[:]}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("client server secret: %w", err)
	}

	statelessResetVal, err := config.GetOrInit(configClientStatelessReset, func(ck ConfigKey) (ConfigValue, error) {
		var key quic.StatelessResetKey
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return ConfigValue{}, fmt.Errorf("generate rand: %w", err)
		}
		return ConfigValue{Bytes: key[:]}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("client server stateless reset key: %w", err)
	}
	var statelessResetKey quic.StatelessResetKey
	copy(statelessResetKey[:], statelessResetVal.Bytes)

	return &clientServer{
		ingresses:         ingresses,
		statelessResetKey: &statelessResetKey,

		auth:   auth,
		relays: relays,
		logger: logger.With("server", "control-clients"),

		reconnect: &reconnectToken{[32]byte(serverSecret.Bytes)},

		conns: conns,
		peers: peers,

		peersCache:  peersCache,
		peersOffset: peersOffset,

		endpointExpiry: endpointExpiry,
	}, nil
}

type clientServer struct {
	ingresses         []Ingress
	statelessResetKey *quic.StatelessResetKey

	auth   ClientAuthenticator
	relays ClientRelays
	logger *slog.Logger

	reconnect *reconnectToken

	conns logc.KV[ClientConnKey, ClientConnValue]
	peers logc.KV[ClientPeerKey, ClientPeerValue]

	peersCache  map[peerKey][]peerValue
	peersOffset int64
	peersMu     sync.RWMutex

	endpointExpiry time.Duration
	connsWg        sync.WaitGroup
}

type peerKey struct {
	endpoint model.Endpoint
	role     model.Role
}

type peerValue struct {
	connID ConnID
	peer   *pbclient.RemotePeer
}

func (s *clientServer) connected(id ClientID, connID ConnID, auth ClientAuthentication, remote net.Addr, metadata string) error {
	return s.conns.Put(ClientConnKey{id, connID}, ClientConnValue{auth, remote.String(), metadata})
}

func (s *clientServer) disconnected(id ClientID, connID ConnID) error {
	return s.conns.Del(ClientConnKey{id, connID})
}

func (s *clientServer) announce(endpoint model.Endpoint, role model.Role, id ClientID, connID ConnID, metadata string, peer *pbclient.Peer) error {
	return s.peers.Put(ClientPeerKey{endpoint, role, id, connID}, ClientPeerValue{Peer: peer, Metadata: metadata})
}

func (s *clientServer) expire(endpoint model.Endpoint, role model.Role, id ClientID, connID ConnID) error {
	key := ClientPeerKey{endpoint, role, id, connID}
	val, err := s.peers.Get(key)
	if err != nil {
		return fmt.Errorf("get peer for expire: %w", err)
	}
	now := time.Now()
	val.ExpiredAt = &now
	return s.peers.Put(key, val)
}

func (s *clientServer) revoke(endpoint model.Endpoint, role model.Role, id ClientID, connID ConnID) error {
	return s.peers.Del(ClientPeerKey{endpoint, role, id, connID})
}

func (s *clientServer) cachedPeers(endpoint model.Endpoint, role model.Role) ([]peerValue, int64) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()

	return slices.Clone(s.peersCache[peerKey{endpoint, role}]), s.peersOffset
}

func (s *clientServer) listen(ctx context.Context, endpoint model.Endpoint, role model.Role, notify func(peers []*pbclient.RemotePeer) error) error {
	peers, offset := s.cachedPeers(endpoint, role)
	doNotify := func() error {
		uniquePeers := map[string]*pbclient.RemotePeer{}
		for _, peer := range peers {
			uniquePeers[peer.peer.Id] = peer.peer
		}

		return notify(slices.Collect(maps.Values(uniquePeers)))
	}
	if err := doNotify(); err != nil {
		return err
	}

	for {
		msgs, nextOffset, err := s.peers.Consume(ctx, offset)
		if err != nil {
			return err
		}

		var changed bool
		for _, msg := range msgs {
			if msg.Key.Endpoint != endpoint || msg.Key.Role != role {
				continue
			}

			if msg.Delete {
				peers = slices.DeleteFunc(peers, func(peer peerValue) bool {
					return peer.peer.Id == msg.Key.ID.string && peer.connID == msg.Key.ConnID
				})
			} else {
				npeer := peerValue{msg.Key.ConnID, &pbclient.RemotePeer{
					Id:       msg.Key.ID.string,
					Metadata: msg.Value.Metadata,
					Peer:     msg.Value.Peer,
				}}
				idx := slices.IndexFunc(peers, func(peer peerValue) bool {
					return peer.peer.Id == msg.Key.ID.string && peer.connID == msg.Key.ConnID
				})
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
			if err := doNotify(); err != nil {
				return err
			}
		}
	}
}

func (s *clientServer) run(ctx context.Context) error {
	g := reliable.NewGroup(ctx)

	s.connsWg.Add(len(s.ingresses))
	for _, ingress := range s.ingresses {
		g.Go(reliable.Bind(ingress, s.runListener))
	}
	g.Go(s.runPeerCache)
	if s.endpointExpiry > 0 {
		g.Go(s.runPeerExpiry)
	}

	g.Go(logc.ScheduleCompact(s.conns))
	g.Go(logc.ScheduleCompact(s.peers))

	return g.Wait()
}

func (s *clientServer) runListener(ctx context.Context, ingress Ingress) error {
	defer s.connsWg.Done()

	s.logger.Debug("start udp listener", "addr", ingress.Addr)
	udpConn, err := net.ListenUDP("udp", ingress.Addr)
	if err != nil {
		return fmt.Errorf("client server udp listen: %w", err)
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			slogc.Fine(s.logger, "error closing udp listener", "err", err)
		}
	}()

	s.logger.Debug("start quic listener", "addr", ingress.Addr)
	transport := quicc.ServerTransport(udpConn, s.statelessResetKey)
	defer func() {
		if err := transport.Close(); err != nil {
			slogc.Fine(s.logger, "error closing transport", "err", err)
		}
	}()

	tlsConf := ingress.TLS.Clone()
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = iterc.MapVarStrings(model.ClientControlV03)
	}

	quicConf := quicc.ServerConfig()
	if ingress.Restr.IsNotEmpty() {
		quicConf = quicConf.Clone()
		quicConf.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
			if ingress.Restr.IsAllowedAddr(info.RemoteAddr) {
				return quicConf, nil
			}
			return nil, fmt.Errorf("client not allowed from %s", info.RemoteAddr.String())
		}
	}

	l, err := transport.Listen(tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("client server quic listen: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			slogc.Fine(s.logger, "error closing clients listener", "err", err)
		}
	}()

	s.logger.Info("accepting client connections", "addr", transport.Conn.LocalAddr())
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			slogc.Fine(s.logger, "accept error", "err", err)
			return fmt.Errorf("client server quic accept: %w", err)
		}

		cc := &clientConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		s.connsWg.Go(func() {
			cc.run(ctx)
		})
		// go cc.run(ctx)
	}
}

func (s *clientServer) runPeerCache(ctx context.Context) error {
	update := func(msg logc.Message[ClientPeerKey, ClientPeerValue]) error {
		s.peersMu.Lock()
		defer s.peersMu.Unlock()

		key := peerKey{msg.Key.Endpoint, msg.Key.Role}
		peers := s.peersCache[key]
		if msg.Delete {
			peers = slices.DeleteFunc(peers, func(peer peerValue) bool {
				return peer.peer.Id == msg.Key.ID.string && peer.connID == msg.Key.ConnID
			})
			if len(peers) == 0 {
				delete(s.peersCache, key)
			} else {
				s.peersCache[key] = peers
			}
		} else {
			npeer := peerValue{msg.Key.ConnID, &pbclient.RemotePeer{
				Id:       msg.Key.ID.string,
				Metadata: msg.Value.Metadata,
				Peer:     msg.Value.Peer,
			}}
			idx := slices.IndexFunc(peers, func(peer peerValue) bool {
				return peer.peer.Id == msg.Key.ID.string && peer.connID == msg.Key.ConnID
			})
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

func (s *clientServer) runPeerExpiry(ctx context.Context) error {
	// Process existing expired entries from the snapshot
	msgs, offset, err := s.peers.Snapshot()
	if err != nil {
		return fmt.Errorf("expiry snapshot: %w", err)
	}
	for _, msg := range msgs {
		if expiredAt := msg.Value.ExpiredAt; expiredAt != nil {
			if err := s.waitAndRevoke(ctx, msg.Key, *expiredAt); err != nil {
				return fmt.Errorf("expiry wait and revoke: %w", err)
			}
		}
	}

	// Watch for new expired entries
	for {
		msgs, nextOffset, err := s.peers.Consume(ctx, offset)
		if err != nil {
			return fmt.Errorf("expiry consume: %w", err)
		}
		for _, msg := range msgs {
			if expiredAt := msg.Value.ExpiredAt; !msg.Delete && expiredAt != nil {
				if err := s.waitAndRevoke(ctx, msg.Key, *expiredAt); err != nil {
					return fmt.Errorf("expiry wait and revoke: %w", err)
				}
			}
		}
		offset = nextOffset
	}
}

func (s *clientServer) waitAndRevoke(ctx context.Context, key ClientPeerKey, expiredAt time.Time) error {
	remaining := s.endpointExpiry - time.Since(expiredAt)
	if remaining > 0 {
		s.logger.Debug("waiting to expire endpoint", "endpoint", key.Endpoint, "role", key.Role, "wait", remaining)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(remaining):
		}
	}

	return s.revoke(key.Endpoint, key.Role, key.ID, key.ConnID)
}

type clientConn struct {
	server *clientServer
	conn   *quic.Conn
	logger *slog.Logger
	connID ConnID

	clientConnAuth
}

type clientConnAuth struct {
	id       ClientID
	auth     ClientAuthentication
	protocol model.ClientControlNextProto
	metadata string
}

func (c *clientConn) run(ctx context.Context) {
	c.logger.Debug("new client connection", "proto", c.conn.ConnectionState().TLS.NegotiatedProtocol, "remote", c.conn.RemoteAddr())
	defer func() {
		if err := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(c.logger, "error closing connection", "err", err)
		}
	}()

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running client conn", "err", err)
	}
}

func (c *clientConn) runErr(ctx context.Context) error {
	if auth, err := c.authenticate(ctx); err != nil {
		if perr := pberror.GetError(err); perr != nil {
			cerr := c.conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
			err = errors.Join(perr, cerr)
		} else {
			cerr := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "Error while authenticating")
			err = errors.Join(err, cerr)
		}
		return err
	} else {
		c.clientConnAuth = *auth
		c.logger = c.logger.With("client-id", c.id)
		c.connID = NewConnID()
	}

	c.logger.Info("client connected", "addr", c.conn.RemoteAddr(), "metadata", c.metadata)
	defer c.logger.Info("client disconnected", "addr", c.conn.RemoteAddr(), "metadata", c.metadata)

	if err := c.server.connected(c.id, c.connID, c.auth, c.conn.RemoteAddr(), c.metadata); err != nil {
		return err
	}
	defer func() {
		if err := c.server.disconnected(c.id, c.connID); err != nil {
			c.logger.Warn("failed to disconnect client", "id", c.id, "err", err)
		}
	}()

	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			return err
		}

		cs := &clientStream{
			conn:   c,
			stream: stream,
		}
		c.server.connsWg.Go(func() {
			cs.run(ctx)
		})
		// go cs.run(ctx)
	}
}

func (c *clientConn) authenticate(ctx context.Context) (*clientConnAuth, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("client auth stream: %w", err)
	}
	defer func() {
		if err := authStream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing auth stream", "err", err)
		}
	}()

	req := &pbclient.AuthenticateReq{}
	if err := proto.Read(authStream, req); err != nil {
		return nil, fmt.Errorf("client auth read: %w", err)
	}

	protocol := model.GetClientControlNextProto(c.conn)
	auth, err := c.server.auth.Authenticate(ClientAuthenticateRequest{
		Proto:        protocol,
		Token:        req.Token,
		Addr:         c.conn.RemoteAddr(),
		BuildVersion: req.BuildVersion,
	})
	if err != nil {
		perr := pberror.GetError(err)
		if perr == nil {
			perr = pberror.NewError(pberror.Code_AuthenticationFailed, "authentication failed: %v", err)
		}
		if err := proto.Write(authStream, &pbclient.AuthenticateResp{Error: perr}); err != nil {
			return nil, fmt.Errorf("client auth err write: %w", err)
		}
		return nil, fmt.Errorf("auth failed: %w", perr)
	}

	var id ClientID
	if sid, err := c.server.reconnect.openClientID(req.ReconnectToken); err != nil {
		c.logger.Debug("decode failed", "err", err)
		id = NewClientID()
	} else {
		id = sid
	}

	origin, err := pbmodel.AddrPortFromNet(c.conn.RemoteAddr())
	if err != nil {
		err := pberror.NewError(pberror.Code_AuthenticationFailed, "cannot resolve origin: %v", err)
		if err := proto.Write(authStream, &pbclient.AuthenticateResp{Error: err}); err != nil {
			return nil, fmt.Errorf("client auth err write: %w", err)
		}
		return nil, fmt.Errorf("client addr port from net: %w", err)
	}

	retoken, err := c.server.reconnect.sealClientID(id)
	if err != nil {
		c.logger.Debug("encrypting failed", "err", err)
		retoken = nil
	}
	if err := proto.Write(authStream, &pbclient.AuthenticateResp{
		Public:         origin,
		ReconnectToken: retoken,
	}); err != nil {
		return nil, fmt.Errorf("client auth write: %w", err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr(), "proto", protocol, "build", req.BuildVersion)
	return &clientConnAuth{id, auth, protocol, req.Metadata}, nil
}

type clientStream struct {
	conn   *clientConn
	stream *quic.Stream
}

func (s *clientStream) run(ctx context.Context) {
	defer func() {
		if err := s.stream.Close(); err != nil {
			slogc.Fine(s.conn.logger, "error closing client stream", "err", err)
		}
	}()

	if err := s.runErr(ctx); err != nil {
		s.conn.logger.Debug("error while running client stream", "err", err)
	}
}

func (s *clientStream) runErr(ctx context.Context) error {
	req, err := pbclient.ReadRequest(s.stream)
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

func validatePeerCert(endpoint model.Endpoint, peer *pbclient.Peer) *pberror.Error {
	if _, err := x509.ParseCertificate(peer.ClientCertificate); err != nil {
		return pberror.NewError(pberror.Code_AnnounceInvalidClientCertificate, "'%s' client cert is invalid", endpoint)
	}
	if _, err := x509.ParseCertificate(peer.ServerCertificate); err != nil {
		return pberror.NewError(pberror.Code_AnnounceInvalidServerCertificate, "'%s' server cert is invalid", endpoint)
	}
	return nil
}

func (s *clientStream) announce(ctx context.Context, req *pbclient.Request_Announce) error {
	endpoint := model.EndpointFromPB(req.Endpoint)
	role := model.RoleFromPB(req.Role)
	if newEp, err := s.conn.server.auth.Validate(s.conn.auth, endpoint, role); err != nil {
		perr := pberror.GetError(err)
		if perr == nil {
			perr = pberror.NewError(pberror.Code_AnnounceValidationFailed, "failed to validate endpoint '%s': %v", endpoint, err)
		}
		if err := proto.Write(s.stream, &pbclient.Response{Error: perr}); err != nil {
			return fmt.Errorf("client write auth err: %w", err)
		}
		return perr
	} else {
		endpoint = newEp
	}

	if err := validatePeerCert(endpoint, req.Peer); err != nil {
		if err := proto.Write(s.stream, &pbclient.Response{Error: err}); err != nil {
			return fmt.Errorf("client write cert err: %w", err)
		}
		return err
	}

	if err := s.conn.server.announce(endpoint, role, s.conn.id, s.conn.connID, s.conn.metadata, req.Peer); err != nil {
		return err
	}
	defer func() {
		if s.conn.server.endpointExpiry > 0 && s.conn.conn.Context().Err() != nil {
			// Connection dead — mark as expired, consumer will delete after timeout
			if err := s.conn.server.expire(endpoint, role, s.conn.id, s.conn.connID); err != nil {
				s.conn.logger.Warn("failed to expire peer", "id", s.conn.id, "err", err)
			}
			return
		}
		// Connection alive or feature disabled — revoke immediately
		if err := s.conn.server.revoke(endpoint, role, s.conn.id, s.conn.connID); err != nil {
			s.conn.logger.Warn("failed to revoke peer", "id", s.conn.id, "err", err)
		}
	}()

	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(s.stream))

	g.Go(func(ctx context.Context) error {
		for {
			req, err := pbclient.ReadRequest(s.stream)
			if err != nil {
				return err
			}
			if req.Announce == nil {
				respErr := pberror.NewError(pberror.Code_RequestUnknown, "unexpected request")
				if err := proto.Write(s.stream, &pbclient.Response{Error: respErr}); err != nil {
					return fmt.Errorf("client write protocol err: %w", err)
				}
				return err
			}

			if err := validatePeerCert(endpoint, req.Announce.Peer); err != nil {
				if err := proto.Write(s.stream, &pbclient.Response{Error: err}); err != nil {
					return fmt.Errorf("client write cert err: %w", err)
				}
				return err
			}

			if err := s.conn.server.announce(endpoint, role, s.conn.id, s.conn.connID, s.conn.metadata, req.Announce.Peer); err != nil {
				return err
			}
		}
	})

	g.Go(func(ctx context.Context) error {
		defer s.conn.logger.Debug("completed sources notify")
		return s.conn.server.listen(ctx, endpoint, role.Invert(), func(peers []*pbclient.RemotePeer) error {
			s.conn.logger.Debug("updated sources list", "peers", len(peers))

			if err := proto.Write(s.stream, &pbclient.Response{
				Announce: &pbclient.Response_Announce{
					Peers: peers,
				},
			}); err != nil {
				return fmt.Errorf("client announce write: %w", err)
			}

			return nil
		})
	})

	return g.Wait()
}

func (s *clientStream) relay(ctx context.Context, req *pbclient.Request_Relay) error {
	endpoint := model.EndpointFromPB(req.Endpoint)
	role := model.RoleFromPB(req.Role)
	if newEp, err := s.conn.server.auth.Validate(s.conn.auth, endpoint, role); err != nil {
		perr := pberror.GetError(err)
		if perr == nil {
			perr = pberror.NewError(pberror.Code_RelayValidationFailed, "failed to validate destination '%s': %v", endpoint, err)
		}
		if err := proto.Write(s.stream, &pbclient.Response{Error: perr}); err != nil {
			return fmt.Errorf("client relay auth err response: %w", err)
		}
		return perr
	} else {
		endpoint = newEp
	}

	clientCert, err := x509.ParseCertificate(req.ClientCertificate)
	if err != nil {
		err := pberror.NewError(pberror.Code_RelayInvalidCertificate, "invalid certificate: %v", err)
		if err := proto.Write(s.stream, &pbclient.Response{Error: err}); err != nil {
			return fmt.Errorf("client relay cert err response: %w", err)
		}
		return err
	}

	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(s.stream))

	g.Go(func(ctx context.Context) error {
		defer s.conn.logger.Debug("completed relay notify")
		return s.conn.server.relays.Relays(ctx, endpoint, role, clientCert, s.conn.auth, func(relays map[RelayID]*pbclient.Relay) error {
			s.conn.logger.Debug("updated relay list", "relays", len(relays))
			if err := proto.Write(s.stream, &pbclient.Response{
				Relay: &pbclient.Response_Relays{
					Relays: slices.Collect(maps.Values(relays)),
				},
			}); err != nil {
				return fmt.Errorf("client relay response: %w", err)
			}
			return nil
		})
	})

	return g.Wait()
}

func (s *clientStream) unknown(_ context.Context, req *pbclient.Request) error {
	s.conn.logger.Error("unknown request", "req", req)
	err := pberror.NewError(pberror.Code_RequestUnknown, "unknown request: %v", req)
	return proto.Write(s.stream, &pbclient.Response{Error: err})
}

package control

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/proto/pbmodel"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type ClientAuthenticateRequest struct {
	Proto        model.ClientNextProto
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
	Client(ctx context.Context, endpoint model.Endpoint, role model.Role, cert *x509.Certificate, auth ClientAuthentication,
		notify func(map[ksuid.KSUID]relayCacheValue) error) error
}

func newClientServer(
	ingresses []Ingress,
	auth ClientAuthenticator,
	relays ClientRelays,
	config logc.KV[ConfigKey, ConfigValue],
	stores Stores,
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

	reactivate := map[ClientConnKey][]ClientPeerKey{}
	for _, msg := range connsMsgs {
		reactivate[msg.Key] = []ClientPeerKey{}
	}

	peersMsgs, peersOffset, err := peers.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("client peers snapshot: %w", err)
	}

	peersCache := map[cacheKey][]*pbclient.RemotePeer{}
	for _, msg := range peersMsgs {
		if reactivePeers, ok := reactivate[ClientConnKey{msg.Key.ID}]; ok {
			key := cacheKey{msg.Key.Endpoint, msg.Key.Role}
			peersCache[key] = append(peersCache[key], &pbclient.RemotePeer{
				Id:   msg.Key.ID.String(),
				Peer: msg.Value.Peer,
			})
			reactivate[ClientConnKey{msg.Key.ID}] = append(reactivePeers, msg.Key)
		} else {
			logger.Warn("peer without corresponding client, deleting", "endpoint", msg.Key.Endpoint, "role", msg.Key.Role, "id", msg.Key.ID)
			if err := peers.Del(msg.Key); err != nil {
				return nil, fmt.Errorf("delete unowned peer: %w", err)
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

		reactivate: reactivate,
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

	peersCache  map[cacheKey][]*pbclient.RemotePeer
	peersOffset int64
	peersMu     sync.RWMutex

	reactivate   map[ClientConnKey][]ClientPeerKey
	reactivateMu sync.RWMutex
}

func (s *clientServer) connected(id ksuid.KSUID, auth ClientAuthentication, remote net.Addr) error {
	s.reactivateMu.Lock()
	delete(s.reactivate, ClientConnKey{id})
	s.reactivateMu.Unlock()

	return s.conns.Put(ClientConnKey{id}, ClientConnValue{Authentication: auth, Addr: remote.String()})
}

func (s *clientServer) disconnected(id ksuid.KSUID) error {
	return s.conns.Del(ClientConnKey{id})
}

func (s *clientServer) announce(endpoint model.Endpoint, role model.Role, id ksuid.KSUID, peer *pbclient.Peer) error {
	return s.peers.Put(ClientPeerKey{endpoint, role, id}, ClientPeerValue{peer})
}

func (s *clientServer) revoke(endpoint model.Endpoint, role model.Role, id ksuid.KSUID) error {
	return s.peers.Del(ClientPeerKey{endpoint, role, id})
}

func (s *clientServer) announcements(endpoint model.Endpoint, role model.Role) ([]*pbclient.RemotePeer, int64) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()

	return slices.Clone(s.peersCache[cacheKey{endpoint, role}]), s.peersOffset
}

func (s *clientServer) listen(ctx context.Context, endpoint model.Endpoint, role model.Role, notify func(peers []*pbclient.RemotePeer) error) error {
	peers, offset := s.announcements(endpoint, role)
	if err := notify(peers); err != nil {
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
				peers = slices.DeleteFunc(peers, func(peer *pbclient.RemotePeer) bool {
					return peer.Id == msg.Key.ID.String()
				})
			} else {
				npeer := &pbclient.RemotePeer{
					Id:   msg.Key.ID.String(),
					Peer: msg.Value.Peer,
				}
				idx := slices.IndexFunc(peers, func(peer *pbclient.RemotePeer) bool { return peer.Id == msg.Key.ID.String() })
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
	g, ctx := errgroup.WithContext(ctx)

	for _, ingress := range s.ingresses {
		g.Go(func() error { return s.runListener(ctx, ingress) })
	}
	g.Go(func() error { return s.runPeerCache(ctx) })
	g.Go(func() error { return s.runCleaner(ctx) })

	return g.Wait()
}

func (s *clientServer) runListener(ctx context.Context, ingress Ingress) error {
	s.logger.Debug("start udp listener", "addr", ingress.Addr)
	udpConn, err := net.ListenUDP("udp", ingress.Addr)
	if err != nil {
		return fmt.Errorf("client server udp listen: %w", err)
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			s.logger.Debug("error closing udp listener", "err", err)
		}
	}()

	s.logger.Debug("start quic listener", "addr", ingress.Addr)
	transport := quicc.ServerTransport(udpConn, s.statelessResetKey)
	defer func() {
		if err := transport.Close(); err != nil {
			s.logger.Debug("error closing transport", "err", err)
		}
	}()

	tlsConf := ingress.TLS.Clone()
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = model.ClientNextProtos
	}

	quicConf := quicc.StdConfig
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
			s.logger.Debug("error closing clients listener", "err", err)
		}
	}()

	s.logger.Info("accepting client connections", "addr", transport.Conn.LocalAddr())
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			s.logger.Debug("accept error", "err", err)
			return fmt.Errorf("client server quic accept: %w", err)
		}

		cc := &clientConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go cc.run(ctx)
	}
}

func (s *clientServer) runPeerCache(ctx context.Context) error {
	update := func(msg logc.Message[ClientPeerKey, ClientPeerValue]) error {
		s.peersMu.Lock()
		defer s.peersMu.Unlock()

		key := cacheKey{msg.Key.Endpoint, msg.Key.Role}
		peers := s.peersCache[key]
		if msg.Delete {
			peers = slices.DeleteFunc(peers, func(peer *pbclient.RemotePeer) bool {
				return peer.Id == msg.Key.ID.String()
			})
			if len(peers) == 0 {
				delete(s.peersCache, key)
			} else {
				s.peersCache[key] = peers
			}
		} else {
			npeer := &pbclient.RemotePeer{
				Id:   msg.Key.ID.String(),
				Peer: msg.Value.Peer,
			}
			idx := slices.IndexFunc(peers, func(peer *pbclient.RemotePeer) bool { return peer.Id == msg.Key.ID.String() })
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

func (s *clientServer) runCleaner(ctx context.Context) error {
	switch inactive, err := s.waitToReactivate(ctx); {
	case err != nil:
		return err
	case inactive == 0:
		s.logger.Debug("all clients reactivated")
		return nil
	}

	s.reactivateMu.Lock()
	defer s.reactivateMu.Unlock()

	for key, peers := range s.reactivate {
		s.logger.Warn("force disconnecting client", "id", key.ID)
		if err := s.disconnected(key.ID); err != nil {
			return err
		}
		for _, peer := range peers {
			if err := s.revoke(peer.Endpoint, peer.Role, peer.ID); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *clientServer) waitToReactivate(ctx context.Context) (int, error) {
	s.reactivateMu.RLock()
	waitToReactivate := len(s.reactivate)
	s.reactivateMu.RUnlock()

	if waitToReactivate == 0 {
		return 0, nil
	}

	s.logger.Debug("waiting for clients to reactivate", "count", waitToReactivate)
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(time.Minute):
		s.reactivateMu.RLock()
		defer s.reactivateMu.RUnlock()
		return len(s.reactivate), nil
	}
}

type clientConn struct {
	server *clientServer
	conn   *quic.Conn
	logger *slog.Logger

	auth ClientAuthentication
	id   ksuid.KSUID
}

func (c *clientConn) run(ctx context.Context) {
	c.logger.Info("new client connected", "proto", c.conn.ConnectionState().TLS.NegotiatedProtocol, "remote", c.conn.RemoteAddr())
	defer func() {
		if err := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			c.logger.Debug("error closing connection", "err", err)
		}
	}()

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running client conn", "err", err)
	}
}

func (c *clientConn) runErr(ctx context.Context) error {
	if auth, id, err := c.authenticate(ctx); err != nil {
		if perr := pberror.GetError(err); perr != nil {
			cerr := c.conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
			err = errors.Join(perr, cerr)
		} else {
			cerr := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "Error while authenticating")
			err = errors.Join(err, cerr)
		}
		return err
	} else {
		c.auth = auth
		c.id = id
		c.logger = c.logger.With("client-id", id)
	}

	if err := c.server.connected(c.id, c.auth, c.conn.RemoteAddr()); err != nil {
		return err
	}
	defer func() {
		if err := c.server.disconnected(c.id); err != nil {
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
		go cs.run(ctx)
	}
}

func (c *clientConn) authenticate(ctx context.Context) (ClientAuthentication, ksuid.KSUID, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, ksuid.Nil, fmt.Errorf("client auth stream: %w", err)
	}
	//nolint:errcheck
	defer authStream.Close()

	req := &pbclient.Authenticate{}
	if err := proto.Read(authStream, req); err != nil {
		return nil, ksuid.Nil, fmt.Errorf("client auth read: %w", err)
	}

	protocol := model.GetClientNextProto(c.conn)
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
			return nil, ksuid.Nil, fmt.Errorf("client auth err write: %w", err)
		}
		return nil, ksuid.Nil, fmt.Errorf("auth failed: %w", perr)
	}

	var id ksuid.KSUID
	if sid, err := c.server.reconnect.openID(req.ReconnectToken); err != nil {
		c.logger.Debug("decode failed", "err", err)
		id = ksuid.New()
	} else {
		id = sid
	}

	origin, err := pbmodel.AddrPortFromNet(c.conn.RemoteAddr())
	if err != nil {
		err := pberror.NewError(pberror.Code_AuthenticationFailed, "cannot resolve origin: %v", err)
		if err := proto.Write(authStream, &pbclient.AuthenticateResp{Error: err}); err != nil {
			return nil, ksuid.Nil, fmt.Errorf("client auth err write: %w", err)
		}
		return nil, ksuid.Nil, fmt.Errorf("client addr port from net: %w", err)
	}

	retoken, err := c.server.reconnect.sealID(id)
	if err != nil {
		c.logger.Debug("encrypting failed", "err", err)
		retoken = nil
	}
	if err := proto.Write(authStream, &pbclient.AuthenticateResp{
		Public:         origin,
		ReconnectToken: retoken,
	}); err != nil {
		return nil, ksuid.Nil, fmt.Errorf("client auth write: %w", err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr(), "proto", protocol, "build", req.BuildVersion)
	return auth, id, nil
}

type clientStream struct {
	conn   *clientConn
	stream *quic.Stream
}

func (s *clientStream) run(ctx context.Context) {
	defer func() {
		if err := s.stream.Close(); err != nil {
			s.conn.logger.Debug("error closing client stream", "err", err)
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

	if err := s.conn.server.announce(endpoint, role, s.conn.id, req.Peer); err != nil {
		return err
	}
	defer func() {
		if err := s.conn.server.revoke(endpoint, role, s.conn.id); err != nil {
			s.conn.logger.Warn("failed to revoke client", "id", s.conn.id, "err", err)
		}
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
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

			if err := s.conn.server.announce(endpoint, role, s.conn.id, req.Announce.Peer); err != nil {
				return err
			}
		}
	})

	g.Go(func() error {
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
			perr = pberror.NewError(pberror.Code_RelayValidationFailed, "failed to validate desination '%s': %v", endpoint, err)
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

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		connCtx := s.conn.conn.Context()
		<-connCtx.Done()
		return context.Cause(connCtx)
	})

	g.Go(func() error {
		defer s.conn.logger.Debug("completed relay notify")
		return s.conn.server.relays.Client(ctx, endpoint, role, clientCert, s.conn.auth, func(relays map[ksuid.KSUID]relayCacheValue) error {
			s.conn.logger.Debug("updated relay list", "relays", len(relays))

			var addrs []*pbclient.Relay
			for id, value := range relays {
				addrs = append(addrs, &pbclient.Relay{
					Id:                id.String(),
					Addresses:         iterc.MapSlice(value.Hostports, model.HostPort.PB),
					ServerCertificate: value.Cert.Raw,
				})
			}

			if err := proto.Write(s.stream, &pbclient.Response{
				Relay: &pbclient.Response_Relays{
					Relays: addrs,
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

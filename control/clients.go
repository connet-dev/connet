package control

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	"github.com/connet-dev/connet/pbs"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type ClientAuthenticateRequest struct {
	Proto        model.ClientToControlProto
	Token        string
	Addr         net.Addr
	BuildVersion string
}

type ClientAuthenticator interface {
	Authenticate(req ClientAuthenticateRequest) (ClientAuthentication, error)
	Validate(auth ClientAuthentication, fwd model.Forward, role model.Role) (model.Forward, error)
}

type ClientAuthentication []byte

type ClientRelays interface {
	Client(ctx context.Context, fwd model.Forward, role model.Role, cert *x509.Certificate, auth ClientAuthentication,
		notify func(map[ksuid.KSUID]relayCacheValue) error) error
}

func newClientServer(
	ingress []model.IngressConfig,
	cert tls.Certificate,
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

	peersCache := map[cacheKey][]*pbs.ServerPeer{}
	for _, msg := range peersMsgs {
		if reactivePeers, ok := reactivate[ClientConnKey{msg.Key.ID}]; ok {
			key := cacheKey{msg.Key.Forward, msg.Key.Role}
			peersCache[key] = append(peersCache[key], &pbs.ServerPeer{
				Id:                msg.Key.ID.String(),
				Direct:            msg.Value.Peer.Direct,
				Relays:            msg.Value.Peer.Relays,
				Directs:           msg.Value.Peer.Directs,
				ServerCertificate: msg.Value.Peer.ServerCertificate,
				ClientCertificate: msg.Value.Peer.ClientCertificate,
			})
			reactivate[ClientConnKey{msg.Key.ID}] = append(reactivePeers, msg.Key)
		} else {
			logger.Warn("peer without corresponding client, deleting", "fwd", msg.Key.Forward, "role", msg.Key.Role, "id", msg.Key.ID)
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
		ingress: ingress,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   model.ClientToControlNextProtos,
		},
		statelessResetKey: &statelessResetKey,

		auth:   auth,
		relays: relays,
		logger: logger.With("server", "clients"),

		reconnect: &reconnectToken{[32]byte(serverSecret.Bytes)},

		conns: conns,
		peers: peers,

		peersCache:  peersCache,
		peersOffset: peersOffset,

		reactivate: reactivate,
	}, nil
}

type clientServer struct {
	ingress           []model.IngressConfig
	tlsConf           *tls.Config
	statelessResetKey *quic.StatelessResetKey

	auth   ClientAuthenticator
	relays ClientRelays
	logger *slog.Logger

	reconnect *reconnectToken

	conns logc.KV[ClientConnKey, ClientConnValue]
	peers logc.KV[ClientPeerKey, ClientPeerValue]

	peersCache  map[cacheKey][]*pbs.ServerPeer
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
			if msg.Key.Forward != fwd || msg.Key.Role != role {
				continue
			}

			if msg.Delete {
				peers = slices.DeleteFunc(peers, func(peer *pbs.ServerPeer) bool {
					return peer.Id == msg.Key.ID.String()
				})
			} else {
				npeer := &pbs.ServerPeer{
					Id:                msg.Key.ID.String(),
					Direct:            msg.Value.Peer.Direct,
					Relays:            msg.Value.Peer.Relays,
					Directs:           msg.Value.Peer.Directs,
					ServerCertificate: msg.Value.Peer.ServerCertificate,
					ClientCertificate: msg.Value.Peer.ClientCertificate,
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
	g, ctx := errgroup.WithContext(ctx)

	for _, cfg := range s.ingress {
		g.Go(func() error { return s.runListener(ctx, cfg) })
	}
	g.Go(func() error { return s.runPeerCache(ctx) })
	g.Go(func() error { return s.runCleaner(ctx) })

	return g.Wait()
}

func (s *clientServer) runListener(ctx context.Context, cfg model.IngressConfig) error {
	s.logger.Debug("start udp listener")
	udpConn, err := net.ListenUDP("udp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("client server udp listen: %w", err)
	}
	defer udpConn.Close()

	s.logger.Debug("start quic listener")
	transport := quicc.ServerTransport(udpConn, s.statelessResetKey)
	defer transport.Close()

	quicConf := quicc.StdConfig
	if cfg.Restr.IsNotEmpty() {
		quicConf = quicConf.Clone()
		quicConf.GetConfigForClient = func(info *quic.ClientHelloInfo) (*quic.Config, error) {
			if cfg.Restr.IsAllowedAddr(info.RemoteAddr) {
				return quicConf, nil
			}
			return nil, fmt.Errorf("client not allowed from %s", info.RemoteAddr.String())
		}
	}

	l, err := transport.Listen(s.tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("client server quic listen: %w", err)
	}
	defer l.Close()

	s.logger.Info("waiting for connections")
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
				Id:                msg.Key.ID.String(),
				Direct:            msg.Value.Peer.Direct,
				Relays:            msg.Value.Peer.Relays,
				Directs:           msg.Value.Peer.Directs,
				ServerCertificate: msg.Value.Peer.ServerCertificate,
				ClientCertificate: msg.Value.Peer.ClientCertificate,
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
			if err := s.revoke(peer.Forward, peer.Role, peer.ID); err != nil {
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
	conn   quic.Connection
	logger *slog.Logger

	auth ClientAuthentication
	id   ksuid.KSUID
}

func (c *clientConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_Unknown), "connection closed")

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running client conn", "err", err)
	}
}

func (c *clientConn) runErr(ctx context.Context) error {
	if auth, id, err := c.authenticate(ctx); err != nil {
		if perr := pb.GetError(err); perr != nil {
			// TODO handle err
			c.conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
		} else {
			// TODO handle err
			c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "Error while authenticating")
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
	defer authStream.Close()

	req := &pbs.Authenticate{}
	if err := pb.Read(authStream, req); err != nil {
		return nil, ksuid.Nil, fmt.Errorf("client auth read: %w", err)
	}

	proto := model.GetClientToControlProto(c.conn)
	auth, err := c.server.auth.Authenticate(ClientAuthenticateRequest{
		Proto:        proto,
		Token:        req.Token,
		Addr:         c.conn.RemoteAddr(),
		BuildVersion: req.BuildVersion,
	})
	if err != nil {
		perr := pb.GetError(err)
		if perr == nil {
			perr = pb.NewError(pb.Error_AuthenticationFailed, "authentication failed: %v", err)
		}
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: perr}); err != nil {
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

	origin, err := pb.AddrPortFromNet(c.conn.RemoteAddr())
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "cannot resolve origin: %v", err)
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return nil, ksuid.Nil, fmt.Errorf("client auth err write: %w", err)
		}
		return nil, ksuid.Nil, fmt.Errorf("client addr port from net: %w", err)
	}

	retoken, err := c.server.reconnect.sealID(id)
	if err != nil {
		c.logger.Debug("encrypting failed", "err", err)
		retoken = nil
	}
	if err := pb.Write(authStream, &pbs.AuthenticateResp{
		Public:         origin,
		ReconnectToken: retoken,
	}); err != nil {
		return nil, ksuid.Nil, fmt.Errorf("client auth write: %w", err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr(), "proto", proto, "build", req.BuildVersion)
	return auth, id, nil
}

type clientStream struct {
	conn   *clientConn
	stream quic.Stream
}

func (s *clientStream) run(ctx context.Context) {
	defer s.stream.Close()

	if err := s.runErr(ctx); err != nil {
		s.conn.logger.Debug("error while running client stream", "err", err)
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
	if peer.Direct != nil {
		if _, err := x509.ParseCertificate(peer.Direct.ClientCertificate); err != nil {
			return pb.NewError(pb.Error_AnnounceInvalidClientCertificate, "'%s' client cert is invalid", fwd)
		}
		if _, err := x509.ParseCertificate(peer.Direct.ServerCertificate); err != nil {
			return pb.NewError(pb.Error_AnnounceInvalidServerCertificate, "'%s' server cert is invalid", fwd)
		}
		if len(peer.Directs) == 0 {
			peer.Directs = peer.Direct.Addresses
		}
	}
	if len(peer.ClientCertificate) > 0 {
		if _, err := x509.ParseCertificate(peer.ClientCertificate); err != nil {
			return pb.NewError(pb.Error_AnnounceInvalidClientCertificate, "'%s' client cert is invalid", fwd)
		}
	} else if peer.Direct != nil {
		peer.ClientCertificate = peer.Direct.ClientCertificate
	}
	if len(peer.ServerCertificate) > 0 {
		if _, err := x509.ParseCertificate(peer.ServerCertificate); err != nil {
			return pb.NewError(pb.Error_AnnounceInvalidServerCertificate, "'%s' server cert is invalid", fwd)
		}
	} else if peer.Direct != nil {
		peer.ServerCertificate = peer.Direct.ServerCertificate
	}
	return nil
}

func (s *clientStream) announce(ctx context.Context, req *pbs.Request_Announce) error {
	fwd := model.ForwardFromPB(req.Forward)
	role := model.RoleFromPB(req.Role)
	if newFwd, err := s.conn.server.auth.Validate(s.conn.auth, fwd, role); err != nil {
		perr := pb.GetError(err)
		if perr == nil {
			perr = pb.NewError(pb.Error_AnnounceValidationFailed, "failed to validate forward '%s': %v", fwd, err)
		}
		if err := pb.Write(s.stream, &pbs.Response{Error: perr}); err != nil {
			return fmt.Errorf("client write auth err: %w", err)
		}
		return perr
	} else {
		fwd = newFwd
	}

	if err := validatePeerCert(fwd, req.Peer); err != nil {
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			return fmt.Errorf("client write cert err: %w", err)
		}
		return err
	}

	if err := s.conn.server.announce(fwd, role, s.conn.id, req.Peer); err != nil {
		return err
	}
	defer func() {
		if err := s.conn.server.revoke(fwd, role, s.conn.id); err != nil {
			s.conn.logger.Warn("failed to revoke client", "id", s.conn.id, "err", err)
		}
	}()

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
					return fmt.Errorf("client write protocol err: %w", err)
				}
				return err
			}

			if err := validatePeerCert(fwd, req.Announce.Peer); err != nil {
				if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
					return fmt.Errorf("client write cert err: %w", err)
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
				return fmt.Errorf("client announce write: %w", err)
			}

			return nil
		})
	})

	return g.Wait()
}

func (s *clientStream) relay(ctx context.Context, req *pbs.Request_Relay) error {
	fwd := model.ForwardFromPB(req.Forward)
	role := model.RoleFromPB(req.Role)
	if newFwd, err := s.conn.server.auth.Validate(s.conn.auth, fwd, role); err != nil {
		perr := pb.GetError(err)
		if perr == nil {
			perr = pb.NewError(pb.Error_RelayValidationFailed, "failed to validate desination '%s': %v", fwd, err)
		}
		if err := pb.Write(s.stream, &pbs.Response{Error: perr}); err != nil {
			return fmt.Errorf("client relay auth err response: %w", err)
		}
		return perr
	} else {
		fwd = newFwd
	}

	clientCert, err := x509.ParseCertificate(req.ClientCertificate)
	if err != nil {
		err := pb.NewError(pb.Error_RelayInvalidCertificate, "invalid certificate: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
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
		return s.conn.server.relays.Client(ctx, fwd, role, clientCert, s.conn.auth, func(relays map[ksuid.KSUID]relayCacheValue) error {
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
				return fmt.Errorf("client relay response: %w", err)
			}
			return nil
		})
	})

	return g.Wait()
}

func (s *clientStream) unknown(_ context.Context, req *pbs.Request) error {
	s.conn.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(s.stream, &pbc.Response{Error: err})
}

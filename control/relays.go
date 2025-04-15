package control

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"

	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbr"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/restr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type RelayAuthenticateRequest struct {
	Proto        model.RelayToControlProto
	Token        string
	Addr         net.Addr
	BuildVersion string
}

type RelayAuthenticator interface {
	Authenticate(req RelayAuthenticateRequest) (RelayAuthentication, error)
}

type RelayAuthentication interface {
	Allow(fwd model.Forward) bool

	encoding.BinaryMarshaler
}

func newRelayServer(
	addr *net.UDPAddr,
	cert tls.Certificate,
	auth RelayAuthenticator,
	iprestr restr.IP,
	config logc.KV[ConfigKey, ConfigValue],
	stores Stores,
	logger *slog.Logger,
) (*relayServer, error) {
	conns, err := stores.RelayConns()
	if err != nil {
		return nil, fmt.Errorf("relay conns store open: %w", err)
	}

	clients, err := stores.RelayClients()
	if err != nil {
		return nil, fmt.Errorf("relay clients store open: %w", err)
	}

	servers, err := stores.RelayServers()
	if err != nil {
		return nil, fmt.Errorf("relay servers store open: %w", err)
	}

	serverOffsets, err := stores.RelayServerOffsets()
	if err != nil {
		return nil, fmt.Errorf("relay server offsets store open: %w", err)
	}

	forwardsMsgs, forwardsOffset, err := servers.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("relay servers snapshot: %w", err)
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

	serverIDConfig, err := config.GetOrInit(configServerID, func(_ ConfigKey) (ConfigValue, error) {
		return ConfigValue{String: netc.GenServerName("connet")}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("relay server id: %w", err)
	}

	serverSecret, err := config.GetOrInit(configServerRelaySecret, func(_ ConfigKey) (ConfigValue, error) {
		privateKey := [32]byte{}
		if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
			return ConfigValue{}, fmt.Errorf("generate rand: %w", err)
		}
		return ConfigValue{Bytes: privateKey[:]}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("relay server secret: %w", err)
	}

	statelessResetVal, err := config.GetOrInit(configRelayStatelessReset, func(ck ConfigKey) (ConfigValue, error) {
		var key quic.StatelessResetKey
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return ConfigValue{}, fmt.Errorf("generate rand: %w", err)
		}
		return ConfigValue{Bytes: key[:]}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("relay server stateless reset key: %w", err)
	}
	var statelessResetKey quic.StatelessResetKey
	copy(statelessResetKey[:], statelessResetVal.Bytes)

	return &relayServer{
		addr: addr,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   model.RelayToControlNextProtos,
		},
		statelessResetKey: &statelessResetKey,

		id:      serverIDConfig.String,
		auth:    auth,
		iprestr: iprestr,
		logger:  logger.With("server", "relays"),

		reconnect: &reconnectToken{[32]byte(serverSecret.Bytes)},

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
	addr              *net.UDPAddr
	tlsConf           *tls.Config
	statelessResetKey *quic.StatelessResetKey

	id      string
	auth    RelayAuthenticator
	iprestr restr.IP
	logger  *slog.Logger

	reconnect *reconnectToken

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

	key := RelayClientKey{Forward: fwd, Role: role, Key: model.NewKey(cert)}
	val := RelayClientValue{Cert: cert}
	if err := s.clients.Put(key, val); err != nil {
		return err
	}
	defer func() {
		if err := s.clients.Del(key); err != nil {
			s.logger.Warn("failed to delete client", "key", key, "err", err)
		}
	}()

	return s.listen(ctx, fwd, notifyFn)
}

func (s *relayServer) listen(ctx context.Context, fwd model.Forward,
	notifyFn func(map[ksuid.KSUID]relayCacheValue) error) error {

	servers, offset := s.getForward(fwd)
	if err := notifyFn(servers); err != nil {
		return err
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
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runListener(ctx) })
	g.Go(func() error { return s.runForwardsCache(ctx) })

	return g.Wait()
}

var errRelayConnectNotAllowed = errors.New("relay not allowed")

func (s *relayServer) runListener(ctx context.Context) error {
	s.logger.Debug("start udp listener")
	udpConn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return fmt.Errorf("relay server udp listen: %w", err)
	}
	defer udpConn.Close()

	s.logger.Debug("start quic listener")
	transport := quicc.ServerTransport(udpConn, s.statelessResetKey)
	defer transport.Close()

	quicConf := quicc.StdConfig
	if s.iprestr.IsNotEmpty() {
		quicConf = quicConf.Clone()
		quicConf.GetConfigForClient = func(info *quic.ClientHelloInfo) (*quic.Config, error) {
			if s.iprestr.IsAllowedAddr(info.RemoteAddr) {
				return quicConf, nil
			}
			return nil, errRelayConnectNotAllowed
		}
	}

	l, err := transport.Listen(s.tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("relay server quic listen: %w", err)
	}
	defer l.Close()

	s.logger.Info("waiting for connections")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			s.logger.Debug("accept error", "err", err)
			return fmt.Errorf("relay server quic accept: %w", err)
		}

		rc := &relayConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go rc.run(ctx)
	}
}

func (s *relayServer) runForwardsCache(ctx context.Context) error {
	update := func(msg logc.Message[RelayServerKey, RelayServerValue]) {
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
	}

	for {
		s.forwardsMu.RLock()
		offset := s.forwardsOffset
		s.forwardsMu.RUnlock()

		msgs, nextOffset, err := s.servers.Consume(ctx, offset)
		if err != nil {
			return fmt.Errorf("relay servers consume: %w", err)
		}

		for _, msg := range msgs {
			update(msg)
		}

		s.forwardsMu.Lock()
		s.forwardsOffset = nextOffset
		s.forwardsMu.Unlock()
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

type relayConnAuth struct {
	id       ksuid.KSUID
	auth     RelayAuthentication
	hostport model.HostPort
}

func (c *relayConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_Unknown), "connection closed")

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running zzz", "err", err)
	}
}

func (c *relayConn) runErr(ctx context.Context) error {
	if rauth, err := c.authenticate(ctx); err != nil {
		if perr := pb.GetError(err); perr != nil {
			c.conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
		} else {
			c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "Error while authenticating")
		}
		return err
	} else {
		c.id = rauth.id
		c.auth = rauth.auth
		c.hostport = rauth.hostport
		c.logger = c.logger.With("relay", c.hostport)
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
	defer func() {
		if err := c.server.conns.Del(key); err != nil {
			c.logger.Warn("failed to delete conn", "key", key, "err", err)
		}
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return c.runRelayClients(ctx) })
	g.Go(func() error { return c.runRelayForwards(ctx) })
	g.Go(func() error { return c.runRelayServers(ctx) })

	return g.Wait()
}

func (c *relayConn) authenticate(ctx context.Context) (*relayConnAuth, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth accept stream: %w", err)
	}
	defer authStream.Close()

	req := &pbr.AuthenticateReq{}
	if err := pb.Read(authStream, req); err != nil {
		return nil, fmt.Errorf("auth read request: %w", err)
	}

	proto := model.GetRelayToControlProto(c.conn)
	auth, err := c.server.auth.Authenticate(RelayAuthenticateRequest{
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
		if err := pb.Write(authStream, &pbr.AuthenticateResp{Error: perr}); err != nil {
			return nil, fmt.Errorf("relay auth err write: %w", err)
		}
		return nil, fmt.Errorf("auth failed: %w", perr)
	}

	var id ksuid.KSUID
	if sid, err := c.server.reconnect.openID(req.ReconnectToken); err != nil {
		c.logger.Debug("decode failed", "err", err)
		id = ksuid.New()
	} else {
		id = sid
	}

	retoken, err := c.server.reconnect.sealID(id)
	if err != nil {
		c.logger.Debug("encrypting failed", "err", err)
		retoken = nil
	}
	if err := pb.Write(authStream, &pbr.AuthenticateResp{
		ControlId:      c.server.id,
		ReconnectToken: retoken,
	}); err != nil {
		return nil, fmt.Errorf("auth write response: %w", err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr(), "proto", proto, "build", req.BuildVersion)
	return &relayConnAuth{id, auth, model.HostPortFromPB(req.Addr)}, nil
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
				return fmt.Errorf("unknown change: %v", change.Change)
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

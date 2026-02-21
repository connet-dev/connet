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
	"sync"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/logc"
	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/proto/pbrelay"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/nacl/box"
	protobuf "google.golang.org/protobuf/proto"
)

type RelayAuthenticateRequest struct {
	Proto        model.RelayControlNextProto
	Token        string
	Addr         net.Addr
	BuildVersion string
}

type RelayAuthenticator interface {
	Authenticate(req RelayAuthenticateRequest) (RelayAuthentication, error)
	Allow(reAuth RelayAuthentication, clAuth ClientAuthentication, endpoint model.Endpoint) (bool, error)
}

type RelayAuthentication []byte

func newRelayServer(
	ingresses []Ingress,
	auth RelayAuthenticator,
	config logc.KV[ConfigKey, ConfigValue],
	stores Stores,
	logger *slog.Logger,
) (*relayServer, error) {
	conns, err := stores.RelayConns()
	if err != nil {
		return nil, fmt.Errorf("relay conns store open: %w", err)
	}

	connsMsgs, connsOffset, err := conns.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("relay conns snapshot: %w", err)
	}
	connsCache := map[RelayID]cachedRelay{}
	for _, msg := range connsMsgs {
		connsCache[msg.Key.ID] = cachedRelay{
			auth:        msg.Value.Authentication,
			authSealKey: msg.Value.AuthenticationSealKey,
			template: &pbclient.Relay{
				Id:                msg.Key.ID.string,
				Addresses:         model.PBsFromHostPorts(msg.Value.Hostports),
				ServerCertificate: msg.Value.Certificate.Raw,
			},
		}
	}

	serverIDConfig, err := config.GetOrInit(configServerID, func(_ ConfigKey) (ConfigValue, error) {
		return ConfigValue{String: netc.GenDomainName("relay.control")}, nil
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
		ingresses:         ingresses,
		statelessResetKey: &statelessResetKey,

		id:     serverIDConfig.String,
		auth:   auth,
		logger: logger.With("server", "control-relays"),

		reconnect: &reconnectToken{[32]byte(serverSecret.Bytes)},

		conns:       conns,
		connsCache:  connsCache,
		connsOffset: connsOffset,
	}, nil
}

type relayServer struct {
	ingresses         []Ingress
	statelessResetKey *quic.StatelessResetKey

	id     string
	auth   RelayAuthenticator
	logger *slog.Logger

	reconnect *reconnectToken

	conns       logc.KV[RelayConnKey, RelayConnValue]
	connsCache  map[RelayID]cachedRelay
	connsOffset int64
	connsMu     sync.RWMutex
}

type cachedRelay struct {
	auth        RelayAuthentication
	authSealKey *[32]byte
	template    *pbclient.Relay
}

func (s *relayServer) cachedRelays() (map[RelayID]cachedRelay, int64) {
	s.connsMu.RLock()
	defer s.connsMu.RUnlock()

	return maps.Clone(s.connsCache), s.connsOffset
}

func (s *relayServer) Relays(ctx context.Context, endpoint model.Endpoint, role model.Role, cert *x509.Certificate, auth ClientAuthentication,
	notify func(map[RelayID]*pbclient.Relay) error) error {

	authenticationData, err := protobuf.Marshal(&pbrelay.ClientAuthentication{
		Endpoint:       endpoint.PB(),
		Role:           role.PB(),
		CertificateKey: model.NewKey(cert).String(),
	})
	if err != nil {
		return fmt.Errorf("signature data error: %w", err)
	}
	seal := func(key *[32]byte) []byte {
		var nonce [24]byte
		rand.Read(nonce[:]) // nolint:errcheck
		return box.SealAfterPrecomputation(nonce[:], authenticationData, &nonce, key)
	}

	localRelays := map[RelayID]*pbclient.Relay{}

	// load initial state
	globalRelays, offset := s.cachedRelays()
	for id, relay := range globalRelays {
		if ok, err := s.auth.Allow(relay.auth, auth, endpoint); err != nil {
			return fmt.Errorf("auth allow error: %w", err)
		} else if ok {
			localRelays[id] = &pbclient.Relay{
				Id:                relay.template.Id,
				Addresses:         relay.template.Addresses,
				ServerCertificate: relay.template.ServerCertificate,
				Authentication:    seal(relay.authSealKey),
				Metadata:          relay.template.Metadata,
			}
		}
	}
	if err := notify(localRelays); err != nil {
		return err
	}

	for {
		msgs, nextOffset, err := s.conns.Consume(ctx, offset)
		if err != nil {
			return err
		}

		var changed bool
		for _, msg := range msgs {
			if msg.Delete {
				delete(localRelays, msg.Key.ID)
				changed = true
			} else if ok, err := s.auth.Allow(msg.Value.Authentication, auth, endpoint); err != nil {
				return fmt.Errorf("auth allow error: %w", err)
			} else if ok {
				localRelays[msg.Key.ID] = &pbclient.Relay{
					Id:                msg.Key.ID.string,
					Addresses:         model.PBsFromHostPorts(msg.Value.Hostports),
					ServerCertificate: msg.Value.Certificate.Raw,
					Authentication:    seal(msg.Value.AuthenticationSealKey),
					Metadata:          msg.Value.Metadata,
				}
				changed = true
			}
		}

		offset = nextOffset

		if changed {
			if err := notify(localRelays); err != nil {
				return err
			}
		}
	}
}

func (s *relayServer) run(ctx context.Context) error {
	g := reliable.NewGroup(ctx)

	for _, ingress := range s.ingresses {
		g.Go(reliable.Bind(ingress, s.runListener))
	}
	g.Go(s.runConnsCache)

	g.Go(logc.ScheduleCompact(s.conns))

	return g.Wait()
}

func (s *relayServer) runListener(ctx context.Context, ingress Ingress) error {
	s.logger.Debug("start udp listener", "addr", ingress.Addr)
	udpConn, err := net.ListenUDP("udp", ingress.Addr)
	if err != nil {
		return fmt.Errorf("relay server udp listen: %w", err)
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
		tlsConf.NextProtos = iterc.MapVarStrings(model.RelayControlV03)
	}

	quicConf := quicc.ServerConfig()
	if ingress.Restr.IsNotEmpty() {
		quicConf = quicConf.Clone()
		quicConf.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
			if ingress.Restr.IsAllowedAddr(info.RemoteAddr) {
				return quicConf, nil
			}
			return nil, fmt.Errorf("relay not allowed from %s", info.RemoteAddr.String())
		}
	}

	l, err := transport.Listen(tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("relay server quic listen: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			slogc.Fine(s.logger, "error closing relays listener", "err", err)
		}
	}()

	s.logger.Info("accepting relay connections", "addr", transport.Conn.LocalAddr())
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			slogc.Fine(s.logger, "accept error", "err", err)
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

func (s *relayServer) runConnsCache(ctx context.Context) error {
	update := func(msg logc.Message[RelayConnKey, RelayConnValue]) {
		s.connsMu.Lock()
		defer s.connsMu.Unlock()

		if msg.Delete {
			delete(s.connsCache, msg.Key.ID)
		} else {
			s.connsCache[msg.Key.ID] = cachedRelay{
				auth:        msg.Value.Authentication,
				authSealKey: msg.Value.AuthenticationSealKey,
				template: &pbclient.Relay{
					Id:                msg.Key.ID.string,
					Addresses:         model.PBsFromHostPorts(msg.Value.Hostports),
					ServerCertificate: msg.Value.Certificate.Raw,
					Metadata:          msg.Value.Metadata,
				},
			}
		}

		s.connsOffset = msg.Offset + 1
	}

	for {
		s.connsMu.RLock()
		offset := s.connsOffset
		s.connsMu.RUnlock()

		msgs, nextOffset, err := s.conns.Consume(ctx, offset)
		if err != nil {
			return fmt.Errorf("relay conns consume: %w", err)
		}

		for _, msg := range msgs {
			update(msg)
		}

		s.connsMu.Lock()
		s.connsOffset = nextOffset
		s.connsMu.Unlock()
	}
}

type relayConn struct {
	server *relayServer
	conn   *quic.Conn
	logger *slog.Logger

	relayConnAuth
}

type relayConnAuth struct {
	id          RelayID
	auth        RelayAuthentication
	hostports   []model.HostPort
	metadata    string
	protocol    model.RelayControlNextProto
	certificate *x509.Certificate
	authSignKey *[32]byte
}

func (c *relayConn) run(ctx context.Context) {
	defer func() {
		if err := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(c.logger, "error closing connection", "err", err)
		}
	}()
	c.logger.Debug("new relay connection", "proto", c.conn.ConnectionState().TLS.NegotiatedProtocol, "remote", c.conn.RemoteAddr())

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running relay conn", "err", err)
	}
}

func (c *relayConn) runErr(ctx context.Context) error {
	if rauth, err := c.authenticate(ctx); err != nil {
		if perr := pberror.GetError(err); perr != nil {
			cerr := c.conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
			err = errors.Join(perr, cerr)
		} else {
			cerr := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "Error while authenticating")
			err = errors.Join(err, cerr)
		}
		return err
	} else {
		c.relayConnAuth = *rauth
		c.logger = c.logger.With("relay", c.hostports)
	}

	c.logger.Info("relay connected", "addr", c.conn.RemoteAddr(), "metadata", c.metadata)
	defer c.logger.Info("relay disconnected", "addr", c.conn.RemoteAddr(), "metadata", c.metadata)

	key := RelayConnKey{ID: c.id}
	value := RelayConnValue{c.auth, c.hostports, c.metadata, c.certificate, c.authSignKey}
	if err := c.server.conns.Put(key, value); err != nil {
		return err
	}
	defer func() {
		if err := c.server.conns.Del(key); err != nil {
			c.logger.Warn("failed to delete conn", "key", key, "err", err)
		}
	}()

	return quicc.WaitLogRTTStats(ctx, c.conn, c.logger) // v0.14.0 rotate secrets?
}

func (c *relayConn) authenticate(ctx context.Context) (*relayConnAuth, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth accept stream: %w", err)
	}
	defer func() {
		if err := authStream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing relay auth", "err", err)
		}
	}()

	req := &pbrelay.AuthenticateReq{}
	if err := proto.Read(authStream, req); err != nil {
		return nil, fmt.Errorf("auth read request: %w", err)
	}

	protocol := model.RelayControlV03
	cert, err := x509.ParseCertificate(req.ServerCertificate)
	if err != nil {
		perr := pberror.GetError(err)
		if perr == nil {
			perr = pberror.NewError(pberror.Code_AuthenticationFailed, "authentication failed: %v", err)
		}
		if err := proto.Write(authStream, &pbrelay.AuthenticateResp{Error: perr}); err != nil {
			return nil, fmt.Errorf("relay auth err write: %w", err)
		}
		return nil, fmt.Errorf("auth failed: %w", perr)
	}

	auth, err := c.server.auth.Authenticate(RelayAuthenticateRequest{
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
		if err := proto.Write(authStream, &pbrelay.AuthenticateResp{Error: perr}); err != nil {
			return nil, fmt.Errorf("relay auth err write: %w", err)
		}
		return nil, fmt.Errorf("auth failed: %w", perr)
	}

	var id RelayID
	if sid, err := c.server.reconnect.openRelayID(req.ReconnectToken); err != nil {
		c.logger.Debug("decode failed", "err", err)
		id = NewRelayID()
	} else {
		id = sid
	}

	controlPk, controlSk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		perr := pberror.NewError(pberror.Code_AuthenticationFailed, "authentication failed: %v", err)
		if err := proto.Write(authStream, &pbrelay.AuthenticateResp{Error: perr}); err != nil {
			return nil, fmt.Errorf("relay auth err write: %w", err)
		}
		return nil, fmt.Errorf("auth failed: %w", perr)
	}
	if len(req.RelayAuthenticationKey) != 32 {
		perr := pberror.NewError(pberror.Code_AuthenticationFailed, "authentication failed: invalid key")
		if err := proto.Write(authStream, &pbrelay.AuthenticateResp{Error: perr}); err != nil {
			return nil, fmt.Errorf("relay auth err write: %w", err)
		}
		return nil, fmt.Errorf("auth failed: %w", perr)
	}

	retoken, err := c.server.reconnect.sealRelayID(id)
	if err != nil {
		c.logger.Debug("encrypting failed", "err", err)
		retoken = nil
	}
	if err := proto.Write(authStream, &pbrelay.AuthenticateResp{
		ControlId:                c.server.id,
		ReconnectToken:           retoken,
		ControlAuthenticationKey: controlPk[:],
	}); err != nil {
		return nil, fmt.Errorf("auth write response: %w", err)
	}

	var relayPk = [32]byte(req.RelayAuthenticationKey)
	sharedKey := new([32]byte)
	box.Precompute(sharedKey, &relayPk, controlSk)

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr(), "proto", protocol, "build", req.BuildVersion)
	hostports := model.HostPortFromPBs(req.Addresses)
	return &relayConnAuth{id, auth, hostports, req.Metadata, protocol, cert, sharedKey}, nil
}

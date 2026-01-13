package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/certc"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/logc"
	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/pkg/statusc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclientrelay"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/proto/pbrelay"
	"github.com/klev-dev/klevdb"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/nacl/box"
	protobuf "google.golang.org/protobuf/proto"
)

type controlClient struct {
	hostports []model.HostPort
	root      *certc.Cert
	direct    *certc.Cert
	metadata  string

	controlAddr          *net.UDPAddr
	controlToken         string
	controlTLSConf       *tls.Config
	handshakeIdleTimeout time.Duration

	config  logc.KV[ConfigKey, ConfigValue]
	clients logc.KV[ClientKey, ClientValue]
	servers logc.KV[ServerKey, ServerValue]

	serverByNameOffset int64
	serverByName       map[string]*relayServer
	serverByNameMu     sync.RWMutex

	clientsStreamOffset int64
	clientsLogOffset    int64

	authUnsealKey atomic.Pointer[[32]byte]

	connStatus atomic.Value
	logger     *slog.Logger
}

func newControlClient(cfg Config, root *certc.Cert, direct *certc.Cert, configStore logc.KV[ConfigKey, ConfigValue]) (*controlClient, error) {
	clients, err := cfg.Stores.Clients()
	if err != nil {
		return nil, err
	}
	servers, err := cfg.Stores.Servers()
	if err != nil {
		return nil, err
	}

	msgs, serversOffset, err := servers.Snapshot()
	if err != nil {
		return nil, err
	}

	serverByName := map[string]*relayServer{}
	for _, msg := range msgs {
		srv, err := newRelayServer(msg)
		if err != nil {
			return nil, err
		}
		serverByName[srv.name] = srv
	}

	clientsStreamOffset, err := configStore.GetOrDefault(configClientsStreamOffset, ConfigValue{Int64: logc.OffsetOldest})
	if err != nil {
		return nil, err
	}

	clientsLogOffset, err := configStore.GetOrDefault(configClientsLogOffset, ConfigValue{Int64: logc.OffsetOldest})
	if err != nil {
		return nil, err
	}

	hostports := iterc.FlattenSlice(iterc.MapSlice(cfg.Ingress, func(in Ingress) []model.HostPort {
		return in.Hostports
	}))

	c := &controlClient{
		hostports: hostports,
		root:      root,
		direct:    direct,
		metadata:  cfg.Metadata,

		controlAddr:  cfg.ControlAddr,
		controlToken: cfg.ControlToken,
		controlTLSConf: &tls.Config{
			ServerName: cfg.ControlHost,
			RootCAs:    cfg.ControlCAs,
			NextProtos: iterc.MapVarStrings(model.RelayControlV03, model.RelayControlV02),
		},
		handshakeIdleTimeout: cfg.HandshakeIdleTimeout,

		config:  configStore,
		clients: clients,
		servers: servers,

		serverByNameOffset: serversOffset,
		serverByName:       serverByName,

		clientsStreamOffset: clientsStreamOffset.Int64,
		clientsLogOffset:    clientsLogOffset.Int64,

		logger: cfg.Logger.With("client", "relay-control"),
	}
	c.connStatus.Store(statusc.NotConnected)
	return c, nil
}

func (s *controlClient) getClientsStreamOffset() int64 {
	return s.clientsStreamOffset
}

func (s *controlClient) setClientsStreamOffset(v int64) error {
	if err := s.config.Put(configClientsStreamOffset, ConfigValue{Int64: v}); err != nil {
		return err
	}
	s.clientsStreamOffset = v
	return nil
}

func (s *controlClient) getClientsLogOffset() int64 {
	return s.clientsLogOffset
}

func (s *controlClient) setClientsLogOffset(v int64) error {
	if err := s.config.Put(configClientsLogOffset, ConfigValue{Int64: v}); err != nil {
		return err
	}
	s.clientsLogOffset = v
	return nil
}

func (s *controlClient) getServer(name string) *relayServer {
	s.serverByNameMu.RLock()
	defer s.serverByNameMu.RUnlock()

	return s.serverByName[name]
}

func (s *controlClient) tlsAuthenticate(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	if srv := s.getServer(chi.ServerName); srv != nil {
		return &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: srv.tls,
			ClientCAs:    srv.cas.Load(),
			NextProtos:   iterc.MapVarStrings(model.ConnectRelayV01),
		}, nil
	}
	return nil, nil
}

func (s *controlClient) v1Auth(serverName string, certs []*x509.Certificate) *clientAuth {
	if srv := s.getServer(serverName); srv != nil {
		return srv.authenticate(certs)
	}
	return nil
}

func (s *controlClient) v2Auth(authReq *pbclientrelay.AuthenticateReq, cert *x509.Certificate) (*clientAuth, error) {
	authUnsealKey := s.authUnsealKey.Load()
	if authUnsealKey == nil {
		return nil, fmt.Errorf("no control verification key")
	}

	decryptNonce := [24]byte(authReq.Authentication)
	authData, ok := box.OpenAfterPrecomputation(nil, authReq.Authentication[24:], &decryptNonce, authUnsealKey)
	if !ok {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "invalid authentication")
	}
	var auth pbrelay.ClientAuthentication
	if err := protobuf.Unmarshal(authData, &auth); err != nil {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "invalid authentication data")
	}
	certKey := model.NewKey(cert)
	if auth.CertificateKey != certKey.String() {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "invalid certificate")
	}

	return &clientAuth{model.EndpointFromPB(auth.Endpoint), model.RoleFromPB(auth.Role), certKey, model.ConnectRelayV02, authReq.Metadata}, nil
}

type TransportsFn func(ctx context.Context) ([]*quic.Transport, error)

func (s *controlClient) run(ctx context.Context, tfn TransportsFn) error {
	return reliable.RunGroup(ctx,
		reliable.Bind(tfn, s.runControl),
		logc.ScheduleCompact(s.config),
		logc.ScheduleCompact(s.clients),
		logc.ScheduleCompact(s.servers),
	)
}

func (s *controlClient) runControl(ctx context.Context, tfn TransportsFn) error {
	defer s.connStatus.Store(statusc.Disconnected)

	s.logger.Info("connecting to control server", "addr", s.controlAddr, "hostports", s.hostports)
	conn, err := s.connect(ctx, tfn)
	if err != nil {
		return err
	}

	var boff reliable.SpinBackoff
	for {
		if err := s.runConnection(ctx, conn); err != nil {
			s.logger.Error("session ended", "err", err)
			if errors.Is(err, context.Canceled) {
				return err
			}
		}

		if err := boff.Wait(ctx); err != nil {
			return err
		}

		s.logger.Info("reconnecting to control server", "addr", s.controlAddr)
		if conn, err = s.reconnect(ctx, tfn); err != nil {
			return err
		}
	}
}

func (s *controlClient) connect(ctx context.Context, tfn TransportsFn) (*quic.Conn, error) {
	transports, err := tfn(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get transports: %w", err)
	}

	reconnConfig, err := s.config.GetOrDefault(configControlReconnect, ConfigValue{})
	if err != nil {
		return nil, fmt.Errorf("server reconnect get: %w", err)
	}

	for _, transport := range transports {
		if conn, err := s.connectSingle(ctx, transport, reconnConfig); err != nil {
			s.logger.Debug("cannot connect relay control server", "localAddr", transport.Conn.LocalAddr(), "err", err)
		} else {
			return conn, nil
		}
	}

	return nil, fmt.Errorf("could not reach the control server on any of the transports")
}

func (s *controlClient) connectSingle(ctx context.Context, transport *quic.Transport, reconnConfig ConfigValue) (*quic.Conn, error) {
	conn, err := transport.Dial(ctx, s.controlAddr, s.controlTLSConf, quicc.ClientConfig(s.handshakeIdleTimeout))
	if err != nil {
		return nil, fmt.Errorf("cannot dial: %w", err)
	}

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() {
		if err := authStream.Close(); err != nil {
			slogc.Fine(s.logger, "relay control server: close stream error", "localAddr", transport.Conn.LocalAddr(), "err", err)
		}
	}()

	switch model.GetRelayControlNextProto(conn) {
	case model.RelayControlV02:
		err = s.authenticateV2(authStream, reconnConfig)
	default:
		err = s.authenticate(authStream, reconnConfig)
	}
	if err != nil {
		perr := pberror.GetError(err)
		if perr == nil {
			perr = pberror.NewError(pberror.Code_AuthenticationFailed, "authentication failed")
		}
		cerr := conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
		return nil, errors.Join(perr, cerr)
	}

	return conn, nil
}

func (s *controlClient) authenticateV2(authStream *quic.Stream, reconnConfig ConfigValue) error {
	if err := proto.Write(authStream, &pbrelay.AuthenticateReq{
		Token:          s.controlToken,
		Addresses:      model.PBsFromHostPorts(s.hostports),
		ReconnectToken: reconnConfig.Bytes,
		BuildVersion:   model.BuildVersion(),
		Metadata:       s.metadata,
	}); err != nil {
		return fmt.Errorf("auth write error: %w", err)
	}

	resp := &pbrelay.AuthenticateResp{}
	if err := proto.Read(authStream, resp); err != nil {
		return fmt.Errorf("auth read error: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("remote error: %w", resp.Error)
	}

	controlIDConfig, err := s.config.GetOrDefault(configControlID, ConfigValue{})
	if err != nil {
		return fmt.Errorf("server control id get: %w", err)
	}
	if controlIDConfig.String != "" && controlIDConfig.String != resp.ControlId {
		return fmt.Errorf("unexpected server id, has: %s, resp: %s", controlIDConfig.String, resp.ControlId)
	}
	controlIDConfig.String = resp.ControlId
	if err := s.config.Put(configControlID, controlIDConfig); err != nil {
		return fmt.Errorf("server control id set: %w", err)
	}

	reconnConfig.Bytes = resp.ReconnectToken
	if err := s.config.Put(configControlReconnect, reconnConfig); err != nil {
		return fmt.Errorf("server reconnect set: %w", err)
	}

	return nil
}

func (s *controlClient) authenticate(authStream *quic.Stream, reconnConfig ConfigValue) error {
	relayPk, relaySk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("could not create keys: %w", err)
	}

	if err := proto.Write(authStream, &pbrelay.AuthenticateReq{
		Token:                  s.controlToken,
		Addresses:              model.PBsFromHostPorts(s.hostports),
		ReconnectToken:         reconnConfig.Bytes,
		BuildVersion:           model.BuildVersion(),
		Metadata:               s.metadata,
		ServerCertificate:      s.direct.Raw(),
		RelayAuthenticationKey: relayPk[:],
	}); err != nil {
		return fmt.Errorf("auth write error: %w", err)
	}

	resp := &pbrelay.AuthenticateResp{}
	if err := proto.Read(authStream, resp); err != nil {
		return fmt.Errorf("auth read error: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("remote error: %w", resp.Error)
	}

	controlIDConfig, err := s.config.GetOrDefault(configControlID, ConfigValue{})
	if err != nil {
		return fmt.Errorf("server control id get: %w", err)
	}
	if controlIDConfig.String != "" && controlIDConfig.String != resp.ControlId {
		return fmt.Errorf("unexpected server id, has: %s, resp: %s", controlIDConfig.String, resp.ControlId)
	}
	controlIDConfig.String = resp.ControlId
	if err := s.config.Put(configControlID, controlIDConfig); err != nil {
		return fmt.Errorf("server control id set: %w", err)
	}

	reconnConfig.Bytes = resp.ReconnectToken
	if err := s.config.Put(configControlReconnect, reconnConfig); err != nil {
		return fmt.Errorf("server reconnect set: %w", err)
	}

	if len(resp.ControlAuthenticationKey) != 32 {
		return fmt.Errorf("invalid control auth key length")
	}

	controlPk := [32]byte(resp.ControlAuthenticationKey)
	sharedKey := new([32]byte)
	box.Precompute(sharedKey, &controlPk, relaySk)
	s.authUnsealKey.Store(sharedKey)

	return nil
}

func (s *controlClient) reconnect(ctx context.Context, tfn TransportsFn) (*quic.Conn, error) {
	d := reliable.MinBackoff
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		s.logger.Debug("backoff wait", "d", d)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}

		if conn, err := s.connect(ctx, tfn); err != nil {
			s.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return conn, nil
		}

		d = reliable.NextBackoff(d)
		t.Reset(d)
	}
}

func (s *controlClient) runConnection(ctx context.Context, conn *quic.Conn) error {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(s.logger, "error closing connection", "err", err)
		}
	}()

	s.connStatus.Store(statusc.Connected)
	defer s.connStatus.Store(statusc.Reconnecting)

	return reliable.RunGroup(ctx,
		reliable.Bind(conn, s.runClientsStream),
		s.runClientsLog,
		s.runServersLog,
		reliable.Bind(conn, s.runServersStream),
		func(ctx context.Context) error { return quicc.WaitLogRTTStats(ctx, conn, s.logger) }, // TODO v0.14.0 exchange auth
	)
}

func (s *controlClient) runClientsStream(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(s.logger, "error closing clients stream", "err", err)
		}
	}()

	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(stream))

	g.Go(func(ctx context.Context) error {
		for {
			req := &pbrelay.ClientsReq{
				Offset: s.getClientsStreamOffset(),
			}
			if err := proto.Write(stream, req); err != nil {
				return err
			}

			resp := &pbrelay.ClientsResp{}
			if err := proto.Read(stream, resp); err != nil {
				return err
			}

			for _, change := range resp.Changes {
				key := ClientKey{
					Endpoint: model.EndpointFromPB(change.Endpoint),
					Role:     model.RoleFromPB(change.Role),
					Key:      model.NewKeyString(change.CertificateKey),
				}

				switch change.Change {
				case pbrelay.ChangeType_ChangePut:
					cert, err := x509.ParseCertificate(change.Certificate)
					if err != nil {
						return err
					}
					if err := s.clients.Put(key, ClientValue{cert}); err != nil {
						return err
					}
				case pbrelay.ChangeType_ChangeDel:
					if err := s.clients.Del(key); err != nil {
						return err
					}
				default:
					return fmt.Errorf("unknown change: %v", change.Change)
				}
			}

			if err := s.setClientsStreamOffset(resp.Offset); err != nil {
				return err
			}
		}
	})

	return g.Wait()
}

func (s *controlClient) runClientsLog(ctx context.Context) error {
	for {
		msgs, nextOffset, err := s.clients.Consume(ctx, s.getClientsLogOffset())
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			srvKey := ServerKey{msg.Key.Endpoint}
			clKey := serverClientKey{msg.Key.Role, msg.Key.Key}
			sv, err := s.servers.Get(srvKey)

			switch {
			case errors.Is(err, klevdb.ErrNotFound):
				serverName := netc.GenDomainName("connet.control.relay")
				serverRoot, err := s.root.NewServer(certc.CertOpts{
					Domains: []string{serverName},
				})
				if err != nil {
					return err
				}
				sv = ServerValue{Name: serverName, Cert: serverRoot}
			case err != nil:
				return err
			}

			if msg.Delete {
				delete(sv.Clients, clKey)
			} else {
				if sv.Clients == nil {
					sv.Clients = map[serverClientKey]ClientValue{}
				}
				sv.Clients[clKey] = msg.Value
			}

			if len(sv.Clients) == 0 {
				if err := s.servers.Del(srvKey); err != nil {
					return err
				}
			} else {
				if err := s.servers.Put(srvKey, sv); err != nil {
					return err
				}
			}
		}

		if err := s.setClientsLogOffset(nextOffset); err != nil {
			return err
		}
	}
}

func (s *controlClient) runServersStream(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(s.logger, "error closing servers stream", "err", err)
		}
	}()

	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(stream))

	g.Go(func(ctx context.Context) error {
		for {
			req := &pbrelay.ServersReq{}
			if err := proto.Read(stream, req); err != nil {
				return err
			}

			var msgs []logc.Message[ServerKey, ServerValue]
			var nextOffset int64
			if req.Offset == logc.OffsetOldest {
				msgs, nextOffset, err = s.servers.Snapshot()
				s.logger.Debug("sending initial control changes", "offset", nextOffset, "changes", len(msgs))
			} else {
				msgs, nextOffset, err = s.servers.Consume(ctx, req.Offset)
				s.logger.Debug("sending delta control changes", "offset", nextOffset, "changes", len(msgs))
			}
			if err != nil {
				return err
			}

			resp := &pbrelay.ServersResp{Offset: nextOffset}

			for _, msg := range msgs {
				var change = &pbrelay.ServersResp_Change{
					Endpoint: msg.Key.Endpoint.PB(),
				}
				if msg.Delete {
					change.Change = pbrelay.ChangeType_ChangeDel
				} else {
					change.ServerCertificate = msg.Value.Cert.Raw()
					change.Change = pbrelay.ChangeType_ChangePut
				}
				resp.Changes = append(resp.Changes, change)
			}

			if err := proto.Write(stream, resp); err != nil {
				return err
			}
		}
	})

	return g.Wait()
}

func (s *controlClient) runServersLog(ctx context.Context) error {
	upsert := func(msg logc.Message[ServerKey, ServerValue]) error {
		serverName := msg.Value.Name

		s.serverByNameMu.RLock()
		srv := s.serverByName[serverName]
		s.serverByNameMu.RUnlock()

		if srv != nil {
			return srv.update(msg)
		}

		s.serverByNameMu.Lock()
		defer s.serverByNameMu.Unlock()

		srv = s.serverByName[serverName]
		if srv != nil {
			return srv.update(msg)
		}

		srv, err := newRelayServer(msg)
		if err != nil {
			return err
		}
		s.serverByName[serverName] = srv
		return nil
	}

	drop := func(msg logc.Message[ServerKey, ServerValue]) error {
		s.serverByNameMu.Lock()
		defer s.serverByNameMu.Unlock()

		delete(s.serverByName, msg.Value.Name)

		return nil
	}

	for {
		msgs, nextOffset, err := s.servers.Consume(ctx, s.serverByNameOffset)
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			if msg.Delete {
				if err := drop(msg); err != nil {
					return err
				}
			} else {
				if err := upsert(msg); err != nil {
					return err
				}
			}
		}

		s.serverByNameOffset = nextOffset
	}
}

type relayServer struct {
	endpoint model.Endpoint
	name     string

	tls []tls.Certificate
	cas atomic.Pointer[x509.CertPool]

	clients map[serverClientKey]*x509.Certificate
	mu      sync.RWMutex
}

func newRelayServer(msg logc.Message[ServerKey, ServerValue]) (*relayServer, error) {
	srvCert, err := msg.Value.Cert.TLSCert()
	if err != nil {
		return nil, err
	}

	srv := &relayServer{
		endpoint: msg.Key.Endpoint,
		name:     srvCert.Leaf.DNSNames[0],

		tls: []tls.Certificate{srvCert},

		clients: map[serverClientKey]*x509.Certificate{},
	}

	cas := x509.NewCertPool()
	for k, v := range msg.Value.Clients {
		srv.clients[k] = v.Cert
		cas.AddCert(v.Cert)
	}
	srv.cas.Store(cas)

	return srv, nil
}

func (s *relayServer) update(msg logc.Message[ServerKey, ServerValue]) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	seenSet := map[serverClientKey]struct{}{}
	cas := x509.NewCertPool()
	for k, v := range msg.Value.Clients {
		if clientCert, ok := s.clients[k]; ok {
			cas.AddCert(clientCert)
		} else {
			s.clients[k] = v.Cert
			cas.AddCert(v.Cert)
		}

		seenSet[k] = struct{}{}
	}
	s.cas.Store(cas)

	for k := range s.clients {
		if _, seen := seenSet[k]; !seen {
			delete(s.clients, k)
		}
	}

	return nil
}

func (s *relayServer) authenticate(certs []*x509.Certificate) *clientAuth {
	cert := certs[0]
	key := model.NewKey(cert)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if dst, ok := s.clients[serverClientKey{model.Destination, key}]; ok && dst.Equal(cert) {
		return &clientAuth{s.endpoint, model.Destination, key, model.ConnectRelayV01, ""}
	}
	if src, ok := s.clients[serverClientKey{model.Source, key}]; ok && src.Equal(cert) {
		return &clientAuth{s.endpoint, model.Source, key, model.ConnectRelayV01, ""}
	}

	return nil
}

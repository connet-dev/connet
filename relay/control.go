package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbr"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/statusc"
	"github.com/klev-dev/klevdb"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type controlClient struct {
	hostports []model.HostPort
	root      *certc.Cert

	controlAddr    *net.UDPAddr
	controlToken   string
	controlTLSConf *tls.Config

	config  logc.KV[ConfigKey, ConfigValue]
	clients logc.KV[ClientKey, ClientValue]
	servers logc.KV[ServerKey, ServerValue]

	serverByNameOffset int64
	serverByName       map[string]*relayServer
	serverByNameMu     sync.RWMutex

	clientsStreamOffset int64
	clientsLogOffset    int64

	connStatus atomic.Value

	logger *slog.Logger
}

func newControlClient(cfg Config, configStore logc.KV[ConfigKey, ConfigValue]) (*controlClient, error) {
	root, err := certc.NewRoot()
	if err != nil {
		return nil, err
	}

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

	c := &controlClient{
		hostports: cfg.Hostports,
		root:      root,

		controlAddr:  cfg.ControlAddr,
		controlToken: cfg.ControlToken,
		controlTLSConf: &tls.Config{
			ServerName: cfg.ControlHost,
			RootCAs:    cfg.ControlCAs,
			NextProtos: model.RelayToControlNextProtos,
		},

		config:  configStore,
		clients: clients,
		servers: servers,

		serverByNameOffset: serversOffset,
		serverByName:       serverByName,

		clientsStreamOffset: clientsStreamOffset.Int64,
		clientsLogOffset:    clientsLogOffset.Int64,

		logger: cfg.Logger.With("relay-control", cfg.Hostports),
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

func (s *controlClient) tlsAuthenticate(chi *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error) {
	if srv := s.getServer(chi.ServerName); srv != nil {
		cfg := base.Clone()
		cfg.Certificates = srv.tls
		cfg.ClientCAs = srv.cas.Load()
		return cfg, nil
	}
	return base, nil
}

func (s *controlClient) authenticate(serverName string, certs []*x509.Certificate) *clientAuth {
	if srv := s.getServer(serverName); srv != nil {
		return srv.authenticate(certs)
	}
	return nil
}

type TransportsFn func(ctx context.Context) ([]*quic.Transport, error)

func (s *controlClient) run(ctx context.Context, tfn TransportsFn) error {
	defer s.connStatus.Store(statusc.Disconnected)

	s.logger.Info("connecting to control server", "addr", s.controlAddr)
	conn, err := s.connect(ctx, tfn)
	if err != nil {
		return err
	}

	var boff netc.SpinBackoff
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

func (s *controlClient) connect(ctx context.Context, tfn TransportsFn) (quic.Connection, error) {
	transports, err := tfn(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get transports: %w", err)
	}

	reconnConfig, err := s.config.GetOrDefault(configControlReconnect, ConfigValue{})
	if err != nil {
		return nil, fmt.Errorf("server reconnect get: %w", err)
	}

	for _, transport := range transports {
		conn, err := transport.Dial(quicc.RTTContext(ctx), s.controlAddr, s.controlTLSConf, quicc.StdConfig)
		if err != nil {
			s.logger.Debug("relay control server: dial error", "localAddr", transport.Conn.LocalAddr(), "err", err)
			continue
		}

		authStream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			s.logger.Debug("relay control server: open stream error", "localAddr", transport.Conn.LocalAddr(), "err", err)
			continue
		}
		defer authStream.Close()

		if err := pb.Write(authStream, &pbr.AuthenticateReq{
			Token:          s.controlToken,
			Addr:           s.hostports[0].PB(),
			Addresses:      iterc.MapSlice(s.hostports, model.HostPort.PB),
			ReconnectToken: reconnConfig.Bytes,
			BuildVersion:   model.BuildVersion(),
		}); err != nil {
			s.logger.Debug("relay control server: auth write error", "localAddr", transport.Conn.LocalAddr(), "err", err)
			continue
		}

		resp := &pbr.AuthenticateResp{}
		if err := pb.Read(authStream, resp); err != nil {
			s.logger.Debug("relay control server: auth read error", "localAddr", transport.Conn.LocalAddr(), "err", err)
			continue
		}
		if resp.Error != nil {
			return nil, resp.Error
		}

		controlIDConfig, err := s.config.GetOrDefault(configControlID, ConfigValue{})
		if err != nil {
			return nil, fmt.Errorf("server control id get: %w", err)
		}
		if controlIDConfig.String != "" && controlIDConfig.String != resp.ControlId {
			return nil, fmt.Errorf("unexpected server id, has: %s, resp: %s", controlIDConfig.String, resp.ControlId)
		}
		controlIDConfig.String = resp.ControlId
		if err := s.config.Put(configControlID, controlIDConfig); err != nil {
			return nil, fmt.Errorf("server control id set: %w", err)
		}

		reconnConfig.Bytes = resp.ReconnectToken
		if err := s.config.Put(configControlReconnect, reconnConfig); err != nil {
			return nil, fmt.Errorf("server reconnect set: %w", err)
		}

		return conn, nil
	}

	return nil, fmt.Errorf("could not reach the control server on any of the transports")
}

func (s *controlClient) reconnect(ctx context.Context, tfn TransportsFn) (quic.Connection, error) {
	d := netc.MinBackoff
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

		d = netc.NextBackoff(d)
		t.Reset(d)
	}
}

func (s *controlClient) runConnection(ctx context.Context, conn quic.Connection) error {
	defer conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_Unknown), "connection closed")

	s.connStatus.Store(statusc.Connected)
	defer s.connStatus.Store(statusc.Reconnecting)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runClientsStream(ctx, conn) })
	g.Go(func() error { return s.runClientsLog(ctx) })
	g.Go(func() error { return s.runServersLog(ctx) })
	g.Go(func() error { return s.runServersStream(ctx, conn) })

	return g.Wait()
}

func (s *controlClient) runClientsStream(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	})

	g.Go(func() error {
		for {
			req := &pbr.ClientsReq{
				Offset: s.getClientsStreamOffset(),
			}
			if err := pb.Write(stream, req); err != nil {
				return err
			}

			resp := &pbr.ClientsResp{}
			if err := pb.Read(stream, resp); err != nil {
				return err
			}

			for _, change := range resp.Changes {
				key := ClientKey{
					Forward: model.ForwardFromPB(change.Forward),
					Role:    model.RoleFromPB(change.Role),
					Key:     model.NewKeyString(change.CertificateKey),
				}

				switch change.Change {
				case pbr.ChangeType_ChangePut:
					cert, err := x509.ParseCertificate(change.Certificate)
					if err != nil {
						return err
					}
					if err := s.clients.Put(key, ClientValue{cert}); err != nil {
						return err
					}
				case pbr.ChangeType_ChangeDel:
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
			srvKey := ServerKey{msg.Key.Forward}
			clKey := serverClientKey{msg.Key.Role, msg.Key.Key}
			sv, err := s.servers.Get(srvKey)

			switch {
			case errors.Is(err, klevdb.ErrNotFound):
				serverName := netc.GenServerName("connet-relay")
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

func (s *controlClient) runServersStream(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	})

	g.Go(func() error {
		for {
			req := &pbr.ServersReq{}
			if err := pb.Read(stream, req); err != nil {
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

			resp := &pbr.ServersResp{Offset: nextOffset}

			for _, msg := range msgs {
				var change = &pbr.ServersResp_Change{
					Forward: msg.Key.Forward.PB(),
				}
				if msg.Delete {
					change.Change = pbr.ChangeType_ChangeDel
				} else {
					change.ServerCertificate = msg.Value.Cert.Raw()
					change.Change = pbr.ChangeType_ChangePut
				}
				resp.Changes = append(resp.Changes, change)
			}

			if err := pb.Write(stream, resp); err != nil {
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
	fwd  model.Forward
	name string

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
		fwd:  msg.Key.Forward,
		name: srvCert.Leaf.DNSNames[0],

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
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert := certs[0]
	key := model.NewKey(cert)

	if dst, ok := s.clients[serverClientKey{model.Destination, key}]; ok && dst.Equal(cert) {
		return &clientAuth{s.fwd, model.Destination, key}
	}
	if src, ok := s.clients[serverClientKey{model.Source, key}]; ok && src.Equal(cert) {
		return &clientAuth{s.fwd, model.Source, key}
	}

	return nil
}

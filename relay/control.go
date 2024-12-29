package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbr"
	"github.com/klev-dev/klevdb"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type controlClient struct {
	hostport model.HostPort
	root     *certc.Cert

	controlAddr    *net.UDPAddr
	controlToken   string
	controlTlsConf *tls.Config

	config  logc.KV[ConfigKey, ConfigValue]
	clients logc.KV[ClientKey, ClientValue]
	servers logc.KV[ServerKey, ServerValue]

	serverByNameOffset int64
	serverByName       map[string]*relayServer
	serverByNameMu     sync.RWMutex

	clientsStreamOffset int64
	clientsLogOffset    int64

	logger *slog.Logger
}

func newControlClient(cfg Config) (*controlClient, error) {
	root, err := certc.NewRoot()
	if err != nil {
		return nil, err
	}

	config, err := cfg.Stores.Config()
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

	clientsStreamOffset, err := config.GetOrDefault(configClientsStreamOffset, ConfigValue{Int64: logc.OffsetOldest})
	if err != nil {
		return nil, err
	}

	clientsLogOffset, err := config.GetOrDefault(configClientsLogOffset, ConfigValue{Int64: logc.OffsetOldest})
	if err != nil {
		return nil, err
	}

	return &controlClient{
		hostport: cfg.Hostport,
		root:     root,

		controlAddr:  cfg.ControlAddr,
		controlToken: cfg.ControlToken,
		controlTlsConf: &tls.Config{
			ServerName: cfg.ControlHost,
			RootCAs:    cfg.ControlCAs,
			NextProtos: []string{"connet-relays"},
		},

		config:  config,
		clients: clients,
		servers: servers,

		serverByNameOffset: serversOffset,
		serverByName:       serverByName,

		clientsStreamOffset: clientsStreamOffset.Int64,
		clientsLogOffset:    clientsLogOffset.Int64,

		logger: cfg.Logger.With("relay-control", cfg.Hostport),
	}, nil
}

func (s *controlClient) getClientsStreamOffset() (int64, error) {
	return s.clientsStreamOffset, nil
}

func (s *controlClient) setClientsStreamOffset(v int64) error {
	if err := s.config.Put(configClientsStreamOffset, ConfigValue{Int64: v}); err != nil {
		return err
	}
	s.clientsStreamOffset = v
	return nil
}

func (s *controlClient) getClientsLogOffset() (int64, error) {
	return s.clientsLogOffset, nil
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

func (s *controlClient) clientTLSConfig(chi *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error) {
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

func (s *controlClient) run(ctx context.Context, transport *quic.Transport) error {
	s.logger.Info("connecting to control server", "addr", s.controlAddr)
	conn, err := s.connect(ctx, transport)
	if err != nil {
		return err
	}

	for {
		if err := s.runConnection(ctx, conn); err != nil {
			switch {
			case errors.Is(err, context.Canceled):
				return err
				// TODO other terminal errors
			}
			s.logger.Error("session ended", "err", err)
		}

		s.logger.Info("reconnecting to control server", "addr", s.controlAddr)
		if conn, err = s.reconnect(ctx, transport); err != nil {
			return err
		}
	}
}

var retConnect = kleverr.Ret1[quic.Connection]

func (s *controlClient) connect(ctx context.Context, transport *quic.Transport) (quic.Connection, error) {
	reconnConfig, err := s.config.GetOrDefault(configControlReconnect, ConfigValue{})
	if err != nil {
		return retConnect(err)
	}

	conn, err := transport.Dial(ctx, s.controlAddr, s.controlTlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return retConnect(err)
	}

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return retConnect(err)
	}
	defer authStream.Close()

	if err := pb.Write(authStream, &pbr.AuthenticateReq{
		Token:          s.controlToken,
		Addr:           s.hostport.PB(),
		ReconnectToken: reconnConfig.Bytes,
	}); err != nil {
		return retConnect(err)
	}

	resp := &pbr.AuthenticateResp{}
	if err := pb.Read(authStream, resp); err != nil {
		return retConnect(err)
	}
	if resp.Error != nil {
		return retConnect(resp.Error)
	}

	controlIDConfig, err := s.config.GetOrDefault(configControlID, ConfigValue{})
	if controlIDConfig.String != "" && controlIDConfig.String != resp.ControlId {
		return nil, kleverr.Newf("unexpected server id, has: %s, resp: %s", controlIDConfig.String, resp.ControlId)
	}
	controlIDConfig.String = resp.ControlId
	if err := s.config.Put(configControlID, controlIDConfig); err != nil {
		return retConnect(err)
	}

	reconnConfig.Bytes = resp.ReconnectToken
	if err := s.config.Put(configControlReconnect, reconnConfig); err != nil {
		return retConnect(err)
	}

	return conn, nil
}

func (c *controlClient) reconnect(ctx context.Context, transport *quic.Transport) (quic.Connection, error) {
	d := netc.MinBackoff
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		c.logger.Debug("backoff wait", "d", d)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}

		if conn, err := c.connect(ctx, transport); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return conn, nil
		}

		d = netc.NextBackoff(d)
		t.Reset(d)
	}
}

func (s *controlClient) runConnection(ctx context.Context, conn quic.Connection) error {
	defer conn.CloseWithError(0, "done")

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
			serverOffset, err := s.getClientsStreamOffset()
			if err != nil {
				return err
			}

			req := &pbr.ClientsReq{
				Offset: serverOffset,
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
					Key:     certc.NewKeyString(change.CertificateKey),
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
					return kleverr.New("unknown change")
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
		offset, err := s.getClientsLogOffset()
		if err != nil {
			return err
		}

		msgs, nextOffset, err := s.clients.Consume(ctx, offset)
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			srvKey := ServerKey{msg.Key.Forward}
			clKey := serverClientKey{msg.Key.Role, msg.Key.Key}
			sv, err := s.servers.Get(srvKey)

			switch {
			case errors.Is(err, klevdb.ErrNotFound):
				serverName := model.GenServerName("connet-relay")
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
	key := certc.NewKey(cert)

	if dst, ok := s.clients[serverClientKey{model.Destination, key}]; ok && dst.Equal(cert) {
		return &clientAuth{s.fwd, true, false}
	}
	if src, ok := s.clients[serverClientKey{model.Source, key}]; ok && src.Equal(cert) {
		return &clientAuth{s.fwd, false, true}
	}

	return nil
}

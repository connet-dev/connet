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

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/logc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbr"
	"github.com/klev-dev/klevdb"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type controlClient struct {
	hostport model.HostPort
	root     *certc.Cert
	stores   Stores

	controlAddr    *net.UDPAddr
	controlToken   string
	controlTlsConf *tls.Config

	state atomic.Pointer[controlServerState]

	logger *slog.Logger
}

type controlServerState struct {
	id     string
	parent *controlClient

	config  logc.KV[configKey, configValue]
	clients logc.KV[clientKey, clientValue]
	servers logc.KV[serverKey, serverValue]

	serverByNameOffset int64
	serverByName       map[string]*relayServer
	serverByNameMu     sync.RWMutex

	clientsStreamOffset int64
	clientsLogOffset    int64
}

func newControlServerState(parent *controlClient, id string) (*controlServerState, error) {
	config, err := parent.stores.Config(id)
	if err != nil {
		return nil, err
	}
	clients, err := parent.stores.Clients(id)
	if err != nil {
		return nil, err
	}
	servers, err := parent.stores.Servers(id)
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

	clientsStreamOffset, err := config.GetOrDefault(configClientsStreamOffset, configValue{Int64: logc.OffsetOldest})
	if err != nil {
		return nil, err
	}

	clientsLogOffset, err := config.GetOrDefault(configClientsLogOffset, configValue{Int64: logc.OffsetOldest})
	if err != nil {
		return nil, err
	}

	return &controlServerState{
		id:     id,
		parent: parent,

		config:  config,
		clients: clients,
		servers: servers,

		serverByNameOffset: serversOffset,
		serverByName:       serverByName,

		clientsStreamOffset: clientsStreamOffset.Int64,
		clientsLogOffset:    clientsLogOffset.Int64,
	}, nil
}

func (s *controlServerState) getClientsStreamOffset() (int64, error) {
	return s.clientsStreamOffset, nil
}

func (s *controlServerState) setClientsStreamOffset(v int64) error {
	if err := s.config.Put(configClientsStreamOffset, configValue{Int64: v}); err != nil {
		return err
	}
	s.clientsStreamOffset = v
	return nil
}

func (s *controlServerState) getClientsLogOffset() (int64, error) {
	return s.clientsLogOffset, nil
}

func (s *controlServerState) setClientsLogOffset(v int64) error {
	if err := s.config.Put(configClientsLogOffset, configValue{Int64: v}); err != nil {
		return err
	}
	s.clientsLogOffset = v
	return nil
}

func (s *controlServerState) getServer(name string) *relayServer {
	s.serverByNameMu.RLock()
	defer s.serverByNameMu.RUnlock()

	return s.serverByName[name]
}

func (s *controlServerState) close() error {
	var errs []error
	errs = append(errs, s.servers.Close())
	errs = append(errs, s.clients.Close())
	errs = append(errs, s.config.Close())
	return errors.Join(errs...)
}

func (s *controlClient) setServerID(serverID string) (*controlServerState, error) {
	switch state := s.state.Load(); {
	case state != nil && state.id == serverID:
		// we've got the correct state, do nothing
		s.logger.Info("same control server, resuming", "serverID", state.id)
		return state, nil
	case state != nil && state.id != serverID:
		s.logger.Info("new control server, destroying state", "serverID", state.id)
		if err := state.close(); err != nil {
			return nil, err
		}
		fallthrough
	default:
		s.logger.Info("new control server, loading state", "serverID", serverID)
		state, err := newControlServerState(s, serverID)
		if err != nil {
			return nil, err
		}
		s.state.Store(state)
		return state, nil
	}
}

func (s *controlClient) getByName(serverName string) *relayServer {
	if state := s.state.Load(); state != nil {
		return state.getServer(serverName)
	}
	return nil
}

func (s *controlClient) clientTLSConfig(chi *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error) {
	if srv := s.getByName(chi.ServerName); srv != nil {
		cfg := base.Clone()
		cfg.Certificates = srv.tls
		cfg.ClientCAs = srv.cas.Load()
		return cfg, nil
	}
	return base, nil
}

func (s *controlClient) authenticate(serverName string, certs []*x509.Certificate) *clientAuth {
	if srv := s.getByName(serverName); srv != nil {
		return srv.authenticate(certs)
	}
	return nil
}

func (s *controlClient) run(ctx context.Context, transport *quic.Transport) error {
	s.logger.Info("connecting to control server", "addr", s.controlAddr)
	conn, serverID, err := s.connect(ctx, transport)
	if err != nil {
		return err
	}

	for {
		if err := s.runConnection(ctx, conn, serverID); err != nil {
			switch {
			case errors.Is(err, context.Canceled):
				return err
				// TODO other terminal errors
			}
			s.logger.Error("session ended", "err", err)
		}

		s.logger.Info("reconnecting to control server", "addr", s.controlAddr)
		if conn, serverID, err = s.reconnect(ctx, transport); err != nil {
			return err
		}
	}
}

var retConnect = kleverr.Ret2[quic.Connection, string]

func (s *controlClient) connect(ctx context.Context, transport *quic.Transport) (quic.Connection, string, error) {
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
		Token: s.controlToken,
		Addr:  s.hostport.PB(),
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

	return conn, resp.ControlId, nil
}

func (c *controlClient) reconnect(ctx context.Context, transport *quic.Transport) (quic.Connection, string, error) {
	d := netc.MinBackoff
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		c.logger.Debug("backoff wait", "d", d)
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-t.C:
		}

		if sess, serverID, err := c.connect(ctx, transport); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return sess, serverID, nil
		}

		d = netc.NextBackoff(d)
		t.Reset(d)
	}
}

func (s *controlClient) runConnection(ctx context.Context, conn quic.Connection, serverID string) error {
	defer conn.CloseWithError(0, "done")

	state, err := s.setServerID(serverID)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return state.runClientsStream(ctx, conn) })
	g.Go(func() error { return state.runClientsLog(ctx) })
	g.Go(func() error { return state.runServersLog(ctx) })
	g.Go(func() error { return state.runServersStream(ctx, conn) })

	return g.Wait()
}

func (s *controlServerState) runClientsStream(ctx context.Context, conn quic.Connection) error {
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
				key := clientKey{
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
					if err := s.clients.Put(key, clientValue{cert}); err != nil {
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

func (s *controlServerState) runClientsLog(ctx context.Context) error {
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
			srvKey := serverKey{msg.Key.Forward}
			clKey := serverClientKey{msg.Key.Role, msg.Key.Key}
			sv, err := s.servers.Get(srvKey)

			switch {
			case errors.Is(err, klevdb.ErrNotFound):
				serverName := model.GenServerName("connet-relay")
				serverRoot, err := s.parent.root.NewServer(certc.CertOpts{
					Domains: []string{serverName},
				})
				if err != nil {
					return err
				}
				sv = serverValue{Name: serverName, Cert: serverRoot}
			case err != nil:
				return err
			}

			if msg.Delete {
				delete(sv.Clients, clKey)
			} else {
				if sv.Clients == nil {
					sv.Clients = map[serverClientKey]clientValue{}
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

func (s *controlServerState) runServersStream(ctx context.Context, conn quic.Connection) error {
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

			var msgs []logc.Message[serverKey, serverValue]
			var nextOffset int64
			if req.Offset == logc.OffsetOldest {
				msgs, nextOffset, err = s.servers.Snapshot()
				s.parent.logger.Debug("sending initial control changes", "offset", nextOffset, "changes", len(msgs))
			} else {
				msgs, nextOffset, err = s.servers.Consume(ctx, req.Offset)
				s.parent.logger.Debug("sending delta control changes", "offset", nextOffset, "changes", len(msgs))
			}
			if err != nil {
				return err
			}

			resp := &pbr.ServersResp{Offset: nextOffset}

			for _, msg := range msgs {
				var change = &pbr.ServersResp_Change{
					Server: msg.Key.Forward.PB(),
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

func (s *controlServerState) runServersLog(ctx context.Context) error {
	upsert := func(msg logc.Message[serverKey, serverValue]) error {
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

	drop := func(msg logc.Message[serverKey, serverValue]) error {
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

func newRelayServer(msg logc.Message[serverKey, serverValue]) (*relayServer, error) {
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

func (s *relayServer) update(msg logc.Message[serverKey, serverValue]) error {
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

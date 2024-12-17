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

	serverID         string
	serverOffset     int64
	serversByForward map[model.Forward]*relayServer
	serversByName    map[string]*relayServer
	serversMu        sync.RWMutex
	serversLog       logc.KV[model.Forward, *x509.Certificate]

	logger *slog.Logger
}

func (s *controlClient) setServerID(serverID string) {
	if s.serverID == serverID {
		return
	} else if s.serverID == "" {
		s.logger.Info("new control server, no state", "serverID", serverID)
		s.serverID = serverID
		return
	}

	s.logger.Info("new control server, resetting", "serverID", serverID)
	s.serversMu.Lock()
	defer s.serversMu.Unlock()

	s.serverID = serverID
	s.serverOffset = logc.OffsetOldest
	s.serversByForward = map[model.Forward]*relayServer{}
	s.serversByName = map[string]*relayServer{}
	s.serversLog = logc.NewMemoryKVLog[model.Forward, *x509.Certificate]()
}

func (s *controlClient) getByName(serverName string) *relayServer {
	s.serversMu.RLock()
	defer s.serversMu.RUnlock()

	return s.serversByName[serverName]
}

func (s *controlClient) clientTLSConfig(chi *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error) {
	srv := s.getByName(chi.ServerName)
	if srv != nil {
		cfg := base.Clone()
		cfg.Certificates = srv.tls
		cfg.ClientCAs = srv.cas.Load()
		return cfg, nil
	}
	return base, nil
}

func (s *controlClient) authenticate(serverName string, certs []*x509.Certificate) *clientAuth {
	srv := s.getByName(serverName)
	if srv == nil {
		return nil
	}
	return srv.authenticate(certs)
}

func (s *controlClient) run(ctx context.Context, transport *quic.Transport) error {
	conn, serverID, err := s.connect(ctx, transport)
	if err != nil {
		return err
	}

	for {
		if err := s.runConnection(ctx, conn, serverID); err != nil {
			s.logger.Error("session ended", "err", err)
			switch {
			case errors.Is(err, context.Canceled):
				return err
				// TODO other terminal errors
			}
		}

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

	if err := pb.Write(authStream, &pbr.RelayAuth{
		Token: s.controlToken,
		Addr:  s.hostport.PB(),
	}); err != nil {
		return retConnect(err)
	}

	resp := &pbr.RelayAuthResp{}
	if err := pb.Read(authStream, resp); err != nil {
		return retConnect(err)
	}
	if resp.Error != nil {
		return retConnect(err)
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
	s.setServerID(serverID)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runForwards(ctx, conn) })
	g.Go(func() error { return s.runCerts(ctx, conn) })

	return g.Wait()
}

func (s *controlClient) runForwards(ctx context.Context, conn quic.Connection) error {
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
			req := &pbr.RelayClientsReq{
				Offset: s.serverOffset,
			}
			if err := pb.Write(stream, req); err != nil {
				return err
			}

			resp := &pbr.RelayClients{}
			if err := pb.Read(stream, resp); err != nil {
				return err
			}

			for _, change := range resp.Changes {
				cert, err := x509.ParseCertificate(change.ClientCertificate)
				if err != nil {
					return err
				}

				switch {
				case change.Destination != nil:
					fwd := model.NewForwardFromPB(change.Destination)
					if change.Change == pbr.RelayChange_ChangeDel {
						s.removeDestination(fwd, cert)
					} else if err := s.addDestination(fwd, cert); err != nil {
						return err
					}
				case change.Source != nil:
					fwd := model.NewForwardFromPB(change.Source)
					if change.Change == pbr.RelayChange_ChangeDel {
						s.removeSource(fwd, cert)
					} else if err := s.addSource(fwd, cert); err != nil {
						return err
					}
				}
			}

			s.serverOffset = resp.Offset
		}
	})

	return g.Wait()
}

func (s *controlClient) runCerts(ctx context.Context, conn quic.Connection) error {
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
			req := &pbr.RelayServersReq{}
			if err := pb.Read(stream, req); err != nil {
				return err
			}

			var msgs []logc.Message[model.Forward, *x509.Certificate]
			var nextOffset int64
			if req.Offset == logc.OffsetOldest {
				msgs, nextOffset, err = s.serversLog.Snapshot(ctx)
				s.logger.Debug("sending initial control changes", "offset", nextOffset, "changes", len(msgs))
			} else {
				msgs, nextOffset, err = s.serversLog.Consume(ctx, req.Offset)
				s.logger.Debug("sending delta control changes", "offset", nextOffset, "changes", len(msgs))
			}
			if err != nil {
				return err
			}

			resp := &pbr.RelayServers{Offset: nextOffset}

			for _, msg := range msgs {
				var change = &pbr.RelayServers_Change{
					Server: msg.Key.PB(),
				}
				if msg.Delete {
					change.Change = pbr.RelayChange_ChangeDel
				} else {
					change.ServerCertificate = msg.Value.Raw
					change.Change = pbr.RelayChange_ChangePut
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

func (s *controlClient) createServer(fwd model.Forward) (*relayServer, error) {
	if srv := s.getServer(fwd); srv != nil {
		return srv, nil
	}

	serverRoot, err := s.root.NewServer(certc.CertOpts{
		Domains: []string{model.GenServerName("connet-relay")},
	})
	if err != nil {
		return nil, err
	}

	serverCert, err := serverRoot.TLSCert()
	if err != nil {
		return nil, err
	}

	srv := &relayServer{
		fwd: fwd,

		cert: serverCert.Leaf,
		tls:  []tls.Certificate{serverCert},

		desinations: map[certc.Key]*x509.Certificate{},
		sources:     map[certc.Key]*x509.Certificate{},
	}

	s.serversMu.Lock()
	defer s.serversMu.Unlock()

	if added := s.serversByForward[fwd]; added != nil {
		return added, nil
	}

	s.serversByForward[fwd] = srv
	s.serversByName[serverCert.Leaf.DNSNames[0]] = srv
	s.serversLog.Put(fwd, srv.cert)

	return srv, nil
}

func (s *controlClient) addDestination(fwd model.Forward, cert *x509.Certificate) error {
	for {
		srv, err := s.createServer(fwd)
		if err != nil {
			return err
		}
		if srv.addDestination(cert) {
			return nil
		}
	}
}

func (s *controlClient) addSource(fwd model.Forward, cert *x509.Certificate) error {
	for {
		srv, err := s.createServer(fwd)
		if err != nil {
			return err
		}
		if srv.addSource(cert) {
			return nil
		}
	}
}

func (s *controlClient) getServer(fwd model.Forward) *relayServer {
	s.serversMu.RLock()
	defer s.serversMu.RUnlock()

	return s.serversByForward[fwd]
}

func (s *controlClient) removeServer(srv *relayServer) {
	s.serversMu.Lock()
	defer s.serversMu.Unlock()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if !srv.empty() {
		return
	}

	srv.desinations = nil
	srv.sources = nil
	srv.cas.Store(nil)

	delete(s.serversByForward, srv.fwd)
	s.serversLog.Del(srv.fwd)
}

func (s *controlClient) removeDestination(fwd model.Forward, cert *x509.Certificate) {
	srv := s.getServer(fwd)
	if srv == nil {
		return
	}
	if srv.removeDestination(cert) {
		s.removeServer(srv)
	}
}

func (s *controlClient) removeSource(fwd model.Forward, cert *x509.Certificate) {
	srv := s.getServer(fwd)
	if srv == nil {
		return
	}
	if srv.removeSource(cert) {
		s.removeServer(srv)
	}
}

type relayServer struct {
	fwd model.Forward

	cert *x509.Certificate
	tls  []tls.Certificate

	desinations map[certc.Key]*x509.Certificate
	sources     map[certc.Key]*x509.Certificate
	mu          sync.RWMutex

	cas atomic.Pointer[x509.CertPool]
}

func (s *relayServer) authenticate(certs []*x509.Certificate) *clientAuth {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := certc.NewKey(certs[0])
	if dst := s.desinations[key]; dst != nil {
		return &clientAuth{s.fwd, true, false}
	}
	if src := s.sources[key]; src != nil {
		return &clientAuth{s.fwd, false, true}
	}

	return nil
}

func (s *relayServer) refreshCA() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cas := x509.NewCertPool()
	for _, cert := range s.desinations {
		cas.AddCert(cert)
	}
	for _, cert := range s.sources {
		cas.AddCert(cert)
	}
	s.cas.Store(cas)
}

func (s *relayServer) addDestination(cert *x509.Certificate) bool {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.desinations == nil {
		return false
	}

	s.desinations[certc.NewKey(cert)] = cert
	return true
}

func (s *relayServer) addSource(cert *x509.Certificate) bool {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sources == nil {
		return false
	}

	s.sources[certc.NewKey(cert)] = cert
	return true
}

func (s *relayServer) removeDestination(cert *x509.Certificate) bool {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.desinations, certc.NewKey(cert))

	return s.empty()
}

func (s *relayServer) removeSource(cert *x509.Certificate) bool {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sources, certc.NewKey(cert))

	return s.empty()
}

func (s *relayServer) empty() bool {
	return (len(s.desinations) + len(s.sources)) == 0
}

package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr     *net.UDPAddr
	Hostport model.HostPort
	Logger   *slog.Logger

	ControlAddr  *net.UDPAddr
	ControlHost  string
	ControlToken string
	ControlCAs   *x509.CertPool
}

func NewServer(cfg Config) (*Server, error) {
	root, err := certc.NewRoot()
	if err != nil {
		return nil, err
	}

	s := &Server{
		addr:     cfg.Addr,
		hostport: cfg.Hostport,
		tlsConf: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			NextProtos: []string{"connet-relay"},
		},

		controlAddr:  cfg.ControlAddr,
		controlToken: cfg.ControlToken,
		controlTlsConf: &tls.Config{
			ServerName: cfg.ControlHost,
			RootCAs:    cfg.ControlCAs,
			NextProtos: []string{"connet-relays"},
		},

		logger: cfg.Logger.With("relay", cfg.Addr),

		serversRoot:      root,
		serversByForward: notify.NewEmpty[map[model.Forward]*relayServer](),
		serversByName:    map[string]*relayServer{},

		destinations: map[model.Forward]map[certc.Key]*relayConn{},
	}
	s.tlsConf.GetConfigForClient = s.tlsConfigWithClientCA
	return s, nil
}

type Server struct {
	addr     *net.UDPAddr
	hostport model.HostPort
	tlsConf  *tls.Config

	controlAddr    *net.UDPAddr
	controlToken   string
	controlTlsConf *tls.Config

	logger *slog.Logger

	serversRoot      *certc.Cert
	serversByForward *notify.V[map[model.Forward]*relayServer]
	serversByName    map[string]*relayServer

	destinations   map[model.Forward]map[certc.Key]*relayConn
	destinationsMu sync.RWMutex
}

func (s *Server) addDestinations(conn *relayConn) {
	s.destinationsMu.Lock()
	defer s.destinationsMu.Unlock()

	fwdDest := s.destinations[conn.fwd]
	if fwdDest == nil {
		fwdDest = map[certc.Key]*relayConn{}
		s.destinations[conn.fwd] = fwdDest
	}
	fwdDest[conn.key] = conn
}

func (s *Server) removeDestinations(conn *relayConn) {
	s.destinationsMu.Lock()
	defer s.destinationsMu.Unlock()

	fwdDest := s.destinations[conn.fwd]
	delete(fwdDest, conn.key)
	if len(fwdDest) == 0 {
		delete(s.destinations, conn.fwd)
	}
}

func (s *Server) findDestinations(fwd model.Forward) []*relayConn {
	s.destinationsMu.RLock()
	defer s.destinationsMu.RUnlock()

	fwdDest := s.destinations[fwd]
	if fwdDest == nil {
		return nil
	}
	return slices.Collect(maps.Values(fwdDest))
}

func (s *Server) tlsConfigWithClientCA(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	srv := s.serversByName[chi.ServerName]
	if srv != nil {
		cfg := s.tlsConf.Clone()
		cfg.Certificates = srv.tls
		cfg.ClientCAs = srv.cas.Load()
		return cfg, nil
	}
	return s.tlsConf, nil
}

func (s *Server) Run(ctx context.Context) error {
	s.logger.Debug("start udp listener")
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer conn.Close()

	s.logger.Debug("start quic listener")
	tr := &quic.Transport{
		Conn: conn,
		// TODO review other options
	}
	defer tr.Close()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runControl(ctx, tr) })
	g.Go(func() error { return s.runClients(ctx, tr) })

	return g.Wait()
}

type relayServer struct {
	fwd  model.Forward
	cert *x509.Certificate

	desinations map[certc.Key]*x509.Certificate
	sources     map[certc.Key]*x509.Certificate
	mu          sync.RWMutex

	tls []tls.Certificate
	cas atomic.Pointer[x509.CertPool]
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

func (s *relayServer) addDestination(cert *x509.Certificate) {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.desinations[certc.NewKey(cert)] = cert
}

func (s *relayServer) removeDestination(cert *x509.Certificate) {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.desinations, certc.NewKey(cert))
}

func (s *relayServer) addSource(cert *x509.Certificate) {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sources[certc.NewKey(cert)] = cert
}

func (s *relayServer) removeSource(cert *x509.Certificate) {
	defer s.refreshCA()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sources, certc.NewKey(cert))
}

func (s *Server) createServer(fwd model.Forward) (*relayServer, error) {
	if srvs, err := s.serversByForward.Peek(); err != nil {
		// nothing in here, add it
	} else if srv, ok := srvs[fwd]; !ok {
		// not in here, add it
	} else {
		return srv, nil
	}

	serverRoot, err := s.serversRoot.NewServer(certc.CertOpts{
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
		fwd:  fwd,
		cert: serverCert.Leaf,

		desinations: map[certc.Key]*x509.Certificate{},
		sources:     map[certc.Key]*x509.Certificate{},

		tls: []tls.Certificate{serverCert},
	}

	s.serversByForward.Update(func(m map[model.Forward]*relayServer) map[model.Forward]*relayServer {
		if m == nil {
			m = map[model.Forward]*relayServer{}
		} else {
			m = maps.Clone(m)
		}
		m[fwd] = srv

		s.serversByName[serverCert.Leaf.DNSNames[0]] = srv

		return m
	})
	return srv, nil
}

func (s *Server) runControl(ctx context.Context, tr *quic.Transport) error {
	// TODO reconnect loop
	conn, err := tr.Dial(ctx, s.controlAddr, s.controlTlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer authStream.Close()

	if err := pb.Write(authStream, &pbs.RelayAuth{
		Token: s.controlToken,
		Addr:  s.hostport.PB(),
	}); err != nil {
		return err
	}

	resp := &pbs.RelayAuthResp{}
	if err := pb.Read(authStream, resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runControlForwards(ctx, conn) })
	g.Go(func() error { return s.runControlCerts(ctx, conn) })

	return g.Wait()
}

func (s *Server) runControlForwards(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return err
	}

	for {
		req := &pbs.RelayClients{}
		if err := pb.Read(stream, req); err != nil {
			return err
		}
		s.logger.Debug("control updates", "req", req)

		for _, change := range req.Changes {
			cert, err := x509.ParseCertificate(change.ClientCertificate)
			if err != nil {
				return err
			}

			switch {
			case change.Destination != nil:
				fwd := model.NewForwardFromPB(change.Destination)
				srv, err := s.createServer(fwd)
				if err != nil {
					return err
				}
				if change.Change == pbs.RelayChange_ChangeDel {
					srv.removeDestination(cert)
				} else {
					srv.addDestination(cert)
				}
			case change.Source != nil:
				fwd := model.NewForwardFromPB(change.Source)
				srv, err := s.createServer(fwd)
				if err != nil {
					return err
				}
				if change.Change == pbs.RelayChange_ChangeDel {
					srv.removeSource(cert)
				} else {
					srv.addSource(cert)
				}
			}
		}
	}
}

func (s *Server) runControlCerts(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	last := map[model.Forward]struct{}{}
	return s.serversByForward.Listen(ctx, func(t map[model.Forward]*relayServer) error {
		resp := &pbs.RelayServers{}

		for fwd, srv := range t {
			if _, ok := last[fwd]; !ok {
				resp.Changes = append(resp.Changes, &pbs.RelayServers_Change{
					Server:            fwd.PB(),
					ServerCertificate: srv.cert.Raw,
					Change:            pbs.RelayChange_ChangePut,
				})
				last[fwd] = struct{}{}
			}
		}

		for fwd := range last {
			if _, ok := t[fwd]; !ok {
				resp.Changes = append(resp.Changes, &pbs.RelayServers_Change{
					Server: fwd.PB(),
					Change: pbs.RelayChange_ChangeDel,
				})
				delete(last, fwd)
			}
		}

		return pb.Write(stream, resp)
	})
}

func (s *Server) runClients(ctx context.Context, tr *quic.Transport) error {
	l, err := tr.Listen(s.tlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return kleverr.Ret(err)
	}
	defer l.Close()

	s.logger.Info("waiting for connections")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				err = context.Cause(ctx)
			}
			s.logger.Warn("accept error", "err", err)
			return kleverr.Ret(err)
		}
		s.logger.Info("client connected", "local", conn.LocalAddr(), "remote", conn.RemoteAddr())

		rc := &relayConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go rc.run(ctx)
	}
}

type relayConn struct {
	server *Server
	conn   quic.Connection
	logger *slog.Logger

	fwd model.Forward
	key certc.Key
}

func (c *relayConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (s *Server) Authenticate(serverName string, certs []*x509.Certificate) (model.Forward, bool, bool) {
	srv := s.serversByName[serverName]
	if srv == nil {
		return model.Forward{}, false, false
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()

	key := certc.NewKey(certs[0])
	if dst := srv.desinations[key]; dst != nil {
		return srv.fwd, true, false
	}
	if src := srv.sources[key]; src != nil {
		return srv.fwd, false, true
	}

	return model.Forward{}, false, false
}

func (c *relayConn) runErr(ctx context.Context) error {
	serverName := c.conn.ConnectionState().TLS.ServerName
	certs := c.conn.ConnectionState().TLS.PeerCertificates
	fwd, dst, src := c.server.Authenticate(serverName, certs)

	switch {
	case dst:
		c.fwd = fwd
		c.key = certc.NewKey(certs[0])

		c.server.addDestinations(c)
		defer c.server.removeDestinations(c)

		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			go c.runDestinationStream(ctx, stream)
		}
	case src:
		c.fwd = fwd
		c.key = certc.NewKey(certs[0])

		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			go c.runSourceStream(ctx, stream)
		}
	default:
		return kleverr.Newf("invalid authentication, not destination or source")
	}
}

func (c *relayConn) runDestinationStream(ctx context.Context, stream quic.Stream) error {
	defer stream.Close()

	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Heartbeat != nil:
		return c.heartbeat(ctx, stream, req.Heartbeat)
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *relayConn) runSourceStream(ctx context.Context, stream quic.Stream) error {
	defer stream.Close()

	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Connect != nil:
		return c.connect(ctx, stream)
	case req.Heartbeat != nil:
		return c.heartbeat(ctx, stream, req.Heartbeat)
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *relayConn) connect(ctx context.Context, stream quic.Stream) error {
	// TODO get destination only once
	dests := c.server.findDestinations(c.fwd)
	for _, dest := range dests {
		if err := c.connectDestination(ctx, stream, dest); err != nil {
			c.logger.Debug("could not dial destination", "err", err)
		} else {
			// connect was success
			return nil
		}
	}

	err := pb.NewError(pb.Error_DestinationNotFound, "could not dial destinations: %d", len(dests))
	return pb.Write(stream, &pbc.Response{Error: err})
}

func (c *relayConn) connectDestination(ctx context.Context, srcStream quic.Stream, dest *relayConn) error {
	dstStream, err := dest.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Newf("could not open stream: %w", err)
	}

	if err := pb.Write(dstStream, &pbc.Request{
		Connect: &pbc.Request_Connect{},
	}); err != nil {
		return kleverr.Newf("could not write request: %w", err)
	}

	if _, err := pbc.ReadResponse(dstStream); err != nil {
		return kleverr.Newf("could not read response: %w", err)
	}

	if err := pb.Write(srcStream, &pbc.Response{}); err != nil {
		return kleverr.Newf("could not write response: %w", err)
	}

	c.logger.Debug("joining conns", "forward", c.fwd)
	err = netc.Join(ctx, srcStream, dstStream)
	c.logger.Debug("disconnected conns", "forward", c.fwd, "err", err)
	return nil
}

func (c *relayConn) heartbeat(ctx context.Context, stream quic.Stream, hbt *pbc.Heartbeat) error {
	if err := pb.Write(stream, &pbc.Response{Heartbeat: hbt}); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	})

	g.Go(func() error {
		for {
			req, err := pbc.ReadRequest(stream)
			if err != nil {
				return err
			}
			if req.Heartbeat == nil {
				respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
				if err := pb.Write(stream, &pbc.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			if err := pb.Write(stream, &pbc.Response{Heartbeat: req.Heartbeat}); err != nil {
				return err
			}
		}
	})

	return g.Wait()
}

func (c *relayConn) unknown(ctx context.Context, stream quic.Stream, req *pbc.Request) error {
	c.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(stream, &pbc.Response{Error: err})
}

package connet

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keihaya-com/connet/authc"
	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
)

type Server struct {
	serverConfig

	realms   map[string]*realmClients
	realmsMu sync.RWMutex
}

func NewServer(opts ...ServerOption) (*Server, error) {
	cfg := &serverConfig{
		address: "0.0.0.0:19190",
		logger:  slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	return &Server{
		serverConfig: *cfg,
		realms:       map[string]*realmClients{},
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	s.logger.Debug("resolving udp address", "addr", s.address)
	addr, err := net.ResolveUDPAddr("udp", s.address)
	if err != nil {
		return kleverr.Ret(err)
	}

	s.logger.Debug("start udp listener", "addr", addr)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer conn.Close()

	tr := &quic.Transport{
		Conn: conn,
		// TODO review other options
	}
	s.logger.Debug("start quic listener", "addr", addr)
	l, err := tr.Listen(&tls.Config{
		Certificates: []tls.Certificate{*s.certificate},
		NextProtos:   []string{"quic-connet"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return kleverr.Ret(err)
	}

	s.logger.Info("waiting for incoming connections", "addr", addr)
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				s.logger.Info("stopped quic listener", "addr", addr)
				return nil
			}
		}

		scID := ksuid.New()
		sc := &serverClient{
			server: s,
			id:     scID,
			conn:   conn,
			logger: s.logger.With("client-id", scID),
		}
		go sc.run(ctx)
	}
}

func (s *Server) getRealm(name string) *realmClients {
	s.realmsMu.RLock()
	realm := s.realms[name]
	s.realmsMu.RUnlock()
	if realm != nil {
		return realm
	}

	s.realmsMu.Lock()
	defer s.realmsMu.Unlock()
	if realm := s.realms[name]; realm != nil {
		return realm
	}

	realm = &realmClients{
		name:    name,
		targets: map[string]*serverClient{},
	}
	s.realms[name] = realm
	return realm
}

func (s *Server) register(auth authc.Authentication, name string, c *serverClient) error {
	localName, realmName, found := strings.Cut(name, "@")
	if found {
		if !slices.Contains(auth.Realms, realmName) {
			return kleverr.Newf("realm not accessible: %s", realmName)
		}
	} else {
		realmName = auth.SelfRealm
	}

	return s.getRealm(realmName).register(localName, c)
}

func (s *Server) find(auth authc.Authentication, name string) (*serverClient, error) {
	localName, realmName, found := strings.Cut(name, "@")
	if found {
		if !slices.Contains(auth.Realms, realmName) {
			return nil, kleverr.Newf("realm not accessible: %s", realmName)
		}
	} else {
		realmName = auth.SelfRealm
	}

	return s.getRealm(realmName).find(localName)
}

func (s *Server) deregister(c *serverClient) {
	for _, realmName := range c.auth.Realms {
		s.getRealm(realmName).deregister(c)
	}
}

type realmClients struct {
	name    string
	targets map[string]*serverClient
	mu      sync.RWMutex
}

func (r *realmClients) register(name string, c *serverClient) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.targets[name] = c
	// TODO last register wins?
	// TODO multiple targets
	return nil
}

func (r *realmClients) find(name string) (*serverClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.targets[name]
	if !ok {
		return nil, kleverr.Newf("target %s not found in %s realm", name, r.name)
	}
	return c, nil
}

func (r *realmClients) deregister(c *serverClient) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k, v := range r.targets {
		if v.id == c.id {
			delete(r.targets, k)
		}
	}
}

type serverClient struct {
	server *Server
	id     ksuid.KSUID
	conn   quic.Connection
	logger *slog.Logger
	auth   authc.Authentication
}

func (c *serverClient) run(ctx context.Context) {
	auth, err := c.authenticate(ctx)
	if err != nil {
		c.logger.Error("authentication failed", "err", err)
		c.conn.CloseWithError(1, "no auth")
		return
	}
	c.auth = auth

	defer c.server.deregister(c)

	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			c.logger.Error("disconnected", "err", err)
			c.conn.CloseWithError(2, "disconnect")
			return
		}

		ssID := ksuid.New()
		ss := &serverStream{
			client: c,
			id:     ssID,
			stream: stream,
			logger: c.logger.With("stream-id", ssID),
		}
		go ss.run(ctx)
	}
}

var retAuth = kleverr.Ret1[authc.Authentication]

func (c *serverClient) authenticate(ctx context.Context) (authc.Authentication, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return retAuth(err)
	}
	defer authStream.Close()

	req := &pbs.Authenticate{}
	if err := pb.Read(authStream, req); err != nil {
		return retAuth(err)
	}

	auth, err := c.server.auth.Authenticate(req.Token)
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "Invalid or unknown token")
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retAuth(err)
		}
		return retAuth(err)
	}

	origin, err := pb.NewAddrPort(c.conn.RemoteAddr())
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "cannot resolve origin: %v", err)
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retAuth(err)
		}
		return retAuth(err)
	}

	if err := pb.Write(authStream, &pbs.AuthenticateResp{
		Origin: origin,
	}); err != nil {
		return retAuth(err)
	}

	c.logger.Debug("authentication completed", "realms", auth.Realms)
	return auth, nil
}

type serverStream struct {
	client *serverClient
	id     ksuid.KSUID
	stream quic.Stream
	logger *slog.Logger
}

func (s *serverStream) run(ctx context.Context) {
	defer s.stream.Close()

	req, err := pbs.ReadRequest(s.stream)
	if err != nil {
		// TODO error
		return
	}
	s.logger.Debug("incomming request", "req", req)

	switch {
	case req.Register != nil:
		s.register(ctx, req.Register.Name)
	case req.Connect != nil:
		s.connect(ctx, req.Connect.Name)
	default:
		s.unknown(ctx, req)
	}
}

func (s *serverStream) register(ctx context.Context, name string) {
	if err := s.client.server.register(s.client.auth, name, s.client); err != nil {
		// TODO better errors, codes from below
		err := pb.NewError(pb.Error_RegistrationFailed, "registration failed: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			s.logger.Warn("cannot write register response", "err", err)
		}
		return
	}
	s.logger.Info("registered listener", "name", name)

	if err := pb.Write(s.stream, &pbs.Response{}); err != nil {
		s.logger.Warn("cannot write register response", "err", err)
	}
}

func (s *serverStream) connect(ctx context.Context, name string) {
	s.logger.Debug("lookup listener", "name", name)
	otherConn, err := s.client.server.find(s.client.auth, name)
	if err != nil {
		s.logger.Debug("listener lookup failed", "name", name, "err", err)
		err := pb.NewError(pb.Error_ListenerNotFound, "failed to lookup registration: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			s.logger.Warn("failed to write response", "err", err)
		}
		return
	}

	otherStream, err := otherConn.conn.OpenStreamSync(ctx)
	if err != nil {
		s.logger.Debug("listener not connected", "name", name, "err", err)
		err := pb.NewError(pb.Error_ListenerNotConnected, "failed to connect listener: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			s.logger.Warn("failed to write response", "err", err)
		}
		return
	}

	if err := pb.Write(otherStream, &pbc.Request{
		Connect: &pbc.Request_Connect{
			Name: name,
		},
	}); err != nil {
		s.logger.Warn("error while writing request", "name", name, "err", err)
		err := pb.NewError(pb.Error_ListenerRequestFailed, "failed to write client request: %v", err)
		if err := pb.Write(s.stream, &pbs.Response{Error: err}); err != nil {
			s.logger.Warn("failed to write response", "err", err)
		}
		return
	}

	if _, err := pbc.ReadResponse(otherStream); err != nil {
		s.logger.Warn("error while reading response", "name", name, "err", err)
		var respErr *pb.Error
		if !errors.As(err, &respErr) {
			respErr = pb.NewError(pb.Error_ListenerResponseFailed, "failed to read client response: %v", err)
		}
		if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
			s.logger.Warn("failed to write response", "err", err)
		}
		return
	}

	var directAddrs []string
	otherAddrPort, err := netip.ParseAddrPort(otherConn.conn.RemoteAddr().String())
	if err == nil {
		directAddrs = append(directAddrs, otherAddrPort.Addr().String())
	}
	if err := pb.Write(s.stream, &pbs.Response{
		Connect: &pbs.Response_Connect{
			DirectAddresses: directAddrs,
		},
	}); err != nil {
		s.logger.Warn("failed to write response", "err", err)
		return
	}

	s.logger.Info("joining conns", "name", name)
	err = netc.Join(ctx, s.stream, otherStream)
	s.logger.Info("disconnected conns", "name", name, "err", err)
}

func (s *serverStream) unknown(ctx context.Context, req *pbs.Request) {
	s.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	if err := pb.Write(s.stream, &pbc.Response{Error: err}); err != nil {
		s.logger.Warn("could not write response", "err", err)
	}
}

type serverConfig struct {
	address     string
	certificate *tls.Certificate
	logger      *slog.Logger
	auth        authc.Authenticator
}

type ServerOption func(*serverConfig) error

func ServerAddress(address string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.address = address
		return nil
	}
}

func ServerSelfSigned() ServerOption {
	return func(cfg *serverConfig) error {
		if cert, err := certc.SelfSigned(); err != nil {
			return err
		} else {
			cfg.certificate = &cert
			return nil
		}
	}
}

func ServerCertificate(cert, key string) ServerOption {
	return func(cfg *serverConfig) error {
		if cert, err := certc.Load(cert, key); err != nil {
			return err
		} else {
			cfg.certificate = &cert
			return nil
		}
	}
}

func ServerLogger(logger *slog.Logger) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.logger = logger
		return nil
	}
}

func ServerAuthenticator(auth authc.Authenticator) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.auth = auth
		return nil
	}
}

package connet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/keihaya-com/connet/lib/authc"
	"github.com/keihaya-com/connet/lib/certc"
	"github.com/keihaya-com/connet/lib/netc"
	"github.com/keihaya-com/connet/lib/protocol"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
)

type Server struct {
	serverConfig

	addrs   map[string]*ServerClient
	addrsMu sync.RWMutex
}

func NewServer(opts ...ServerOption) (*Server, error) {
	cfg := &serverConfig{
		address: "0.0.0.0:8443",
		logger:  slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	return &Server{
		serverConfig: *cfg,
		addrs:        map[string]*ServerClient{},
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
		sc := &ServerClient{
			server: s,
			id:     scID,
			conn:   conn,
			logger: s.logger.With("client-id", scID),
		}
		go sc.Run(ctx)
	}
}

type ServerClient struct {
	server *Server
	id     ksuid.KSUID
	conn   quic.Connection
	logger *slog.Logger
	auth   authc.Authentication
}

func (c *ServerClient) Run(ctx context.Context) {
	auth, err := c.authenticate(ctx)
	if err != nil {
		c.logger.Error("authentication failed", "err", err)
		c.conn.CloseWithError(1, "no auth")
		return
	}
	c.auth = auth

	defer func() {
		c.server.addrsMu.Lock()
		defer c.server.addrsMu.Unlock()

		for k, v := range c.server.addrs {
			if c.id == v.id {
				delete(c.server.addrs, k)
			}
		}
	}()

	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			c.logger.Error("disconnected", "err", err)
			c.conn.CloseWithError(2, "disconnect")
			return
		}

		ssID := ksuid.New()
		ss := &ServerStream{
			client: c,
			id:     ssID,
			stream: stream,
			logger: c.logger.With("stream-id", ssID),
		}
		go ss.Run(ctx)
	}
}

var retAuth = kleverr.Ret1[authc.Authentication]

func (c *ServerClient) authenticate(ctx context.Context) (authc.Authentication, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return authc.Authentication{}, err
	}
	defer authStream.Close()

	req, authToken, err := protocol.ReadRequest(authStream)
	switch {
	case err != nil:
		return retAuth(err)
	case req != protocol.RequestAuth:
		err := fmt.Errorf("expected auth request, but got %v", req)
		protocol.ResponseAuthExpected.Write(authStream, err.Error())
		return retAuth(err)
	}

	auth, err := c.server.auth.Authenticate(authToken)
	if err != nil {
		err := fmt.Errorf("invalid token: %w", err)
		protocol.ResponseAuthInvalid.Write(authStream, err.Error())
		return retAuth(err)
	}

	if err := protocol.ResponseOk.Write(authStream, "ok"); err != nil {
		return retAuth(err)
	}

	c.logger.Debug("authentication completed", "realms", auth.Realms)
	return auth, nil
}

type ServerStream struct {
	client *ServerClient
	id     ksuid.KSUID
	stream quic.Stream
	logger *slog.Logger
}

func (s *ServerStream) Run(ctx context.Context) {
	req, addr, err := protocol.ReadRequest(s.stream)
	if err != nil {
		return //err
	}
	s.logger.Debug("incomming request", "req", req, "addr", addr)

	switch req {
	case protocol.RequestListen:
		s.listen(ctx, addr)
	case protocol.RequestConnect:
		s.connect(ctx, addr)
	default:
		s.unknown(ctx, req, addr)
	}
}

func (s *ServerStream) listen(ctx context.Context, addr string) {
	s.client.server.addrsMu.Lock()
	s.client.server.addrs[addr] = s.client
	s.client.server.addrsMu.Unlock()

	s.logger.Info("registered listener", "addr", addr)

	if err := protocol.ResponseOk.Write(s.stream, "ok"); err != nil {
		return //err
	}
	if err := s.stream.Close(); err != nil {
		return //err
	}
}

func (s *ServerStream) connect(ctx context.Context, addr string) {
	s.logger.Debug("lookup listener", "addr", addr)
	s.client.server.addrsMu.RLock()
	otherConn, ok := s.client.server.addrs[addr]
	s.client.server.addrsMu.RUnlock()

	if !ok {
		s.logger.Debug("listener not found", "addr", addr)
		if err := protocol.ResponseListenNotFound.Write(s.stream, fmt.Sprintf("%s is not known to this server", addr)); err != nil {
			return // err
		}
		if err := s.stream.Close(); err != nil {
			return // err
		}
		return
	}

	otherStream, err := otherConn.conn.OpenStreamSync(ctx)
	if err != nil {
		s.logger.Debug("listener not connected", "addr", addr, "err", err)
		if err := protocol.ResponseListenNotDialed.Write(s.stream, fmt.Sprintf("%s dial failed: %v", addr, err)); err != nil {
			return // err
		}
		if err := s.stream.Close(); err != nil {
			return // err
		}
		return
	}

	if err := protocol.RequestConnect.Write(otherStream, addr); err != nil {
		// TODO better error response
		s.logger.Debug("could not write connect request", "addr", addr, "err", err)
		if err := protocol.ResponseListenNotDialed.Write(s.stream, fmt.Sprintf("%s dial failed: %v", addr, err)); err != nil {
			return
		}
		if err := s.stream.Close(); err != nil {
			return // err
		}
		return
	}

	otherResp, err := protocol.ReadResponse(otherStream)
	if err != nil {
		s.logger.Debug("could not join", "addr", addr, "err", err)
		if err := protocol.ResponseListenNotDialed.Write(s.stream, fmt.Sprintf("%s dial failed: %v", addr, err)); err != nil {
			return
		}
		if err := s.stream.Close(); err != nil {
			return // err
		}
		return
	}

	if err := protocol.ResponseOk.Write(s.stream, otherResp); err != nil {
		return // err
	}

	s.logger.Info("joining", "addr", addr)
	if err := netc.Join(ctx, s.stream, otherStream); err != nil {
		return // err
	}
}

func (s *ServerStream) unknown(ctx context.Context, req protocol.RequestType, addr string) {
	if err := protocol.ResponseRequestInvalid.Write(s.stream, fmt.Sprintf("%d is not valid request", req)); err != nil {
		return //err
	}
	if err := s.stream.Close(); err != nil {
		return //err
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

package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/lib/protocol"
	"github.com/keihaya-com/connet/netc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type Client struct {
	clientConfig
}

func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := &clientConfig{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	return &Client{
		clientConfig: *cfg,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}

	for {
		sid := ksuid.New()
		s := &ClientSession{
			client: c,
			id:     sid,
			conn:   conn,
			logger: c.logger.With("connection-id", sid),
		}
		if err := s.Run(ctx); err != nil {
			return err
		}

		if conn, err = c.reconnect(ctx); err != nil {
			return err
		}
	}
}

func (c *Client) connect(ctx context.Context) (quic.Connection, error) {
	c.logger.Debug("dialing target", "addr", c.address)
	conn, err := quic.DialAddr(ctx, c.address, &tls.Config{
		RootCAs:            c.cas,
		InsecureSkipVerify: c.insecure,
		NextProtos:         []string{"quic-connet"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return nil, kleverr.Ret(err)
	}

	c.logger.Debug("authenticating", "addr", c.address)
	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	defer authStream.Close()

	if err := protocol.RequestAuth.Write(authStream, c.token); err != nil {
		return nil, kleverr.Ret(err)
	}
	authResp, err := protocol.ReadResponse(authStream)
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	c.logger.Info("authenticated: ", "resp", authResp)

	return conn, nil
}

func (c *Client) reconnect(ctx context.Context) (quic.Connection, error) {
	for {
		time.Sleep(time.Second) // TODO backoff and such

		if conn, err := c.connect(ctx); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return conn, nil
		}
	}
}

type ClientSession struct {
	client *Client
	id     ksuid.KSUID
	conn   quic.Connection
	logger *slog.Logger
}

func (s *ClientSession) Run(ctx context.Context) error {
	for name, addr := range s.client.destinations {
		if err := s.registerDestination(ctx, name, addr); err != nil {
			return err
		}
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return s.runDestinations(ctx)
	})

	for addr, name := range s.client.sources {
		g.Go(func() error {
			return s.runSource(ctx, addr, name)
		})
	}

	return g.Wait()
}

func (s *ClientSession) registerDestination(ctx context.Context, name, addr string) error {
	cmdStream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}

	if err := protocol.RequestRegister.Write(cmdStream, name); err != nil {
		return kleverr.Ret(err)
	}
	result, err := protocol.ReadResponse(cmdStream)
	if err != nil {
		return kleverr.Ret(err)
	}
	s.logger.Info("registered destination", "name", name, "addr", addr, "result", result)
	return nil
}

func (s *ClientSession) runDestinations(ctx context.Context) error {
	for {
		stream, err := s.conn.AcceptStream(ctx)
		if err != nil {
			return kleverr.Ret(err)
		}
		go s.runDestinationRequest(ctx, stream)
	}
}

func (s *ClientSession) runDestinationRequest(ctx context.Context, stream quic.Stream) {
	req, name, err := protocol.ReadRequest(stream)
	if err != nil {
		return
	}

	switch req {
	case protocol.RequestConnect:
		addr, ok := s.client.destinations[name]
		if ok {
			if conn, err := net.Dial("tcp", addr); err != nil {
				if err := protocol.ResponseDestinationDialError.Write(stream, fmt.Sprintf("%s not connected", name)); err != nil {
					return
				}
				if err := stream.Close(); err != nil {
					return
				}
			} else {
				if err := protocol.ResponseOk.Write(stream, fmt.Sprintf("connected to %s", name)); err != nil {
					return
				}

				s.logger.Debug("joining from server", "name", name)
				go func() {
					err := netc.Join(ctx, stream, conn)
					s.logger.Debug("disconnected from server", "name", name, "err", err)
				}()
			}
		} else {
			if err := protocol.ResponseDestinationNotFound.Write(stream, fmt.Sprintf("%s not found", name)); err != nil {
				return
			}
			if err := stream.Close(); err != nil {
				return
			}
		}
	default:
		// TODO logging?
		if err := protocol.ResponseRequestUnknown.Write(stream, fmt.Sprintf("unknown request")); err != nil {
			return
		}
		if err := stream.Close(); err != nil {
			return
		}
	}
}

func (s *ClientSession) runSource(ctx context.Context, addr, name string) error {
	s.logger.Debug("listening for conns", "name", name, "addr", addr)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return kleverr.Ret(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return kleverr.Ret(err)
		}

		go s.runSourceConn(ctx, name, conn)
	}
}

func (s *ClientSession) runSourceConn(ctx context.Context, name string, conn net.Conn) {
	defer conn.Close()

	s.logger.Debug("received conn", "name", name, "remote", conn.RemoteAddr())
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		s.logger.Warn("failed to open server stream", "name", name, "err", err)
		return
	}
	if err := protocol.RequestConnect.Write(stream, name); err != nil {
		s.logger.Warn("failed to request connection", "name", name, "err", err)
		return
	}
	result, err := protocol.ReadResponse(stream)
	if err != nil {
		s.logger.Warn("failed to response connection", "name", name, "err", err)
		return
	}

	s.logger.Debug("joining to server", "name", name, "result", result)
	err = netc.Join(ctx, conn, stream)
	s.logger.Debug("disconnected to server", "name", name, "err", err)
}

type clientConfig struct {
	address      string
	token        string
	sources      map[string]string
	destinations map[string]string
	cas          *x509.CertPool
	insecure     bool
	logger       *slog.Logger
}

type ClientOption func(cfg *clientConfig) error

func ClientServer(addr string) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.address = addr
		return nil
	}
}

func ClientAuthentication(token string) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.token = token
		return nil
	}
}

func ClientSource(addr, name string) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.sources == nil {
			cfg.sources = map[string]string{}
		}
		cfg.sources[addr] = name
		return nil
	}
}

func ClientDestination(name, addr string) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.destinations == nil {
			cfg.destinations = map[string]string{}
		}
		cfg.destinations[name] = addr
		return nil
	}
}

func ClientCA(certFile string, keyFile string) ClientOption {
	return func(cfg *clientConfig) error {
		if cert, err := certc.Load(certFile, keyFile); err != nil {
			return err
		} else {
			pool := x509.NewCertPool()
			pool.AddCert(cert.Leaf)
			cfg.cas = pool
			return nil
		}
	}
}

func ClientInsecure() ClientOption {
	return func(cfg *clientConfig) error {
		cfg.insecure = true
		return nil
	}
}

func ClientLogger(logger *slog.Logger) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.logger = logger
		return nil
	}
}

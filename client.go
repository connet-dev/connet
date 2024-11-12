package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
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
		serverAddress: "127.0.0.1:19190",
		localAddress:  "0.0.0.0:19191",
		logger:        slog.Default(),
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
	c.logger.Debug("resolving udp address", "addr", c.localAddress)
	addr, err := net.ResolveUDPAddr("udp", c.localAddress)
	if err != nil {
		return kleverr.Ret(err)
	}
	c.logger.Debug("start udp listener", "addr", addr)
	localConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer localConn.Close()

	conn, err := c.connect(ctx, localConn)
	if err != nil {
		return err
	}

	for {
		sid := ksuid.New()
		s := &clientSession{
			client: c,
			id:     sid,
			conn:   conn,
			logger: c.logger.With("connection-id", sid),
		}
		if err := s.run(ctx); err != nil {
			return err
		}

		if conn, err = c.reconnect(ctx, localConn); err != nil {
			return err
		}
	}
}

func (c *Client) connect(ctx context.Context, localConn net.PacketConn) (quic.Connection, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", c.serverAddress)
	if err != nil {
		return nil, kleverr.Ret(err)
	}

	c.logger.Debug("dialing target", "addr", c.serverAddress)
	conn, err := quic.Dial(ctx, localConn, serverAddr, &tls.Config{
		RootCAs:            c.cas,
		InsecureSkipVerify: c.insecure,
		NextProtos:         []string{"quic-connet"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return nil, kleverr.Ret(err)
	}

	c.logger.Debug("authenticating", "addr", c.serverAddress)
	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	defer authStream.Close()

	if err := pb.Write(authStream, &pbs.Authenticate{
		Token: c.token,
	}); err != nil {
		return nil, kleverr.Ret(err)
	}

	resp := &pbs.AuthenticateResp{}
	if err := pb.Read(authStream, resp); err != nil {
		return nil, kleverr.Ret(err)
	}
	if resp.Error != nil {
		return nil, kleverr.Ret(resp.Error)
	}

	c.logger.Info("authenticated", "origin", resp.Origin.AsNetip())

	return conn, nil
}

func (c *Client) reconnect(ctx context.Context, localConn net.PacketConn) (quic.Connection, error) {
	for {
		time.Sleep(time.Second) // TODO backoff and such

		if conn, err := c.connect(ctx, localConn); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return conn, nil
		}
	}
}

type clientSession struct {
	client *Client
	id     ksuid.KSUID
	conn   quic.Connection
	logger *slog.Logger
}

func (s *clientSession) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return s.runDirect(ctx)
	})

	g.Go(func() error {
		for name, addr := range s.client.destinations {
			if err := s.registerDestination(ctx, name, addr); err != nil {
				return err
			}
		}
		return s.runDestinations(ctx)
	})

	for addr, name := range s.client.sources {
		g.Go(func() error {
			src := &clientSource{
				sess:            s,
				localAddr:       addr,
				destinationName: name,
				logger:          s.logger.With("addr", addr, "name", name),
			}
			return src.run(ctx)
		})
	}

	return g.Wait()
}

func (s *clientSession) registerDestination(ctx context.Context, name, addr string) error {
	cmdStream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer cmdStream.Close()

	if err := pb.Write(cmdStream, &pbs.Request{
		Register: &pbs.Request_Register{
			Name: name,
		},
	}); err != nil {
		return kleverr.Ret(err)
	}

	if _, err := pbs.ReadResponse(cmdStream); err != nil {
		return kleverr.Ret(err)
	}

	s.logger.Info("registered destination", "name", name, "addr", addr)
	return nil
}

func (s *clientSession) runDestinations(ctx context.Context) error {
	for {
		stream, err := s.conn.AcceptStream(ctx)
		if err != nil {
			return kleverr.Ret(err)
		}
		go s.runDestinationRequest(ctx, stream)
	}
}

func (s *clientSession) runDestinationRequest(ctx context.Context, stream quic.Stream) {
	defer stream.Close()

	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return
	}

	switch {
	case req.Connect != nil:
		s.destinationConnect(ctx, stream, req.Connect.Name)
	default:
		s.unknown(ctx, stream, req)
	}
}

func (s *clientSession) destinationConnect(ctx context.Context, stream quic.Stream, name string) {
	addr, ok := s.client.destinations[name]
	if !ok {
		err := pb.NewError(pb.Error_DestinationNotFound, "%s not found on this client", name)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			s.logger.Warn("could not write response", "name", name, "addr", addr, "err", err)
		}
		return
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		err := pb.NewError(pb.Error_DestinationDialFailed, "%s could not be dialed: %v", name, err)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			s.logger.Warn("could not write response", "name", name, "addr", addr, "err", err)
		}
		return
	}

	if err := pb.Write(stream, &pbc.Response{}); err != nil {
		s.logger.Warn("could not write response", "name", name, "addr", addr, "err", err)
		return
	}

	s.logger.Debug("joining from server", "name", name)
	err = netc.Join(ctx, stream, conn)
	s.logger.Debug("disconnected from server", "name", name, "err", err)
}

func (s *clientSession) unknown(ctx context.Context, stream quic.Stream, req *pbc.Request) {
	s.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
		s.logger.Warn("could not write response", "err", err)
	}
}

func (c *clientSession) runDirect(ctx context.Context) error {

	return nil
}

type clientSource struct {
	sess            *clientSession
	localAddr       string
	destinationName string
	logger          *slog.Logger
}

func (s *clientSource) run(ctx context.Context) error {
	s.logger.Debug("listening for conns")
	l, err := net.Listen("tcp", s.localAddr)
	if err != nil {
		return kleverr.Ret(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return kleverr.Ret(err)
		}

		go s.runConn(ctx, conn)
	}
}

func (s *clientSource) runConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	s.logger.Debug("received conn", "remote", conn.RemoteAddr())
	stream, err := s.sess.conn.OpenStreamSync(ctx)
	if err != nil {
		s.logger.Warn("failed to open server stream", "err", err)
		return
	}
	if err := pb.Write(stream, &pbs.Request{
		Connect: &pbs.Request_Connect{
			Name: s.destinationName,
		},
	}); err != nil {
		s.logger.Warn("failed to request connection", "err", err)
		return
	}

	resp, err := pbs.ReadResponse(stream)
	if err != nil {
		s.logger.Warn("failed to response connection", "err", err)
		return
	}

	s.logger.Debug("joining to server", "direct", resp.Connect.DirectAddresses)
	err = netc.Join(ctx, conn, stream)
	s.logger.Debug("disconnected to server", "err", err)
}

type clientConfig struct {
	serverAddress string
	localAddress  string
	token         string
	sources       map[string]string
	destinations  map[string]string
	cas           *x509.CertPool
	insecure      bool
	logger        *slog.Logger
}

type ClientOption func(cfg *clientConfig) error

func ClientServerAddress(addr string) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.serverAddress = addr
		return nil
	}
}

func ClientLocalAddress(addr string) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.localAddress = addr
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

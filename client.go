package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
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
		logger: slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.serverAddr == nil {
		if err := ClientServerAddress("127.0.0.1:19190")(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.directAddr == nil {
		if err := ClientDirectAddress("0.0.0.0:19192")(cfg); err != nil {
			return nil, err
		}
	}

	return &Client{
		clientConfig: *cfg,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	c.logger.Debug("start udp listener", "addr", c.directAddr)
	localConn, err := net.ListenUDP("udp", c.directAddr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer localConn.Close()

	rootCert, err := certc.NewRoot()
	if err != nil {
		return kleverr.Ret(err)
	}
	c.logger.Debug("generated root cert")

	transport := &quic.Transport{
		Conn: localConn,
	}

	sess, err := c.connect(ctx, transport, rootCert)
	if err != nil {
		return err
	}

	for {
		if err := sess.run(ctx); err != nil {
			c.logger.Error("session ended", "err", err)
			return err
		}

		if sess, err = c.reconnect(ctx, transport, rootCert); err != nil {
			return err
		}
	}
}

func (c *Client) connect(ctx context.Context, transport *quic.Transport, rootCert *certc.Cert) (*clientSession, error) {
	c.logger.Debug("dialing target", "addr", c.serverAddr)
	conn, err := transport.Dial(ctx, c.serverAddr, &tls.Config{
		ServerName: c.serverName,
		RootCAs:    c.cas,
		NextProtos: []string{"connet"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return nil, kleverr.Ret(err)
	}

	c.logger.Debug("authenticating", "addr", c.serverAddr)
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

	c.logger.Info("authenticated", "origin", resp.Public.AsNetip())

	sid := ksuid.New()
	return &clientSession{
		client:      c,
		id:          sid,
		transport:   transport,
		conn:        conn,
		directAddrs: []*pb.AddrPort{resp.Public},
		logger:      c.logger.With("connection-id", sid),
		rootCert:    rootCert,
	}, nil
}

func (c *Client) reconnect(ctx context.Context, transport *quic.Transport, rootCert *certc.Cert) (*clientSession, error) {
	for {
		time.Sleep(time.Second) // TODO backoff and such

		if sess, err := c.connect(ctx, transport, rootCert); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return sess, nil
		}
	}
}

type clientSession struct {
	client      *Client
	id          ksuid.KSUID
	transport   *quic.Transport
	conn        quic.Connection
	directAddrs []*pb.AddrPort // TODO these should be multiple, not only from server pov
	logger      *slog.Logger
	rootCert    *certc.Cert
}

func (s *clientSession) run(ctx context.Context) error {
	intCert, err := s.rootCert.NewIntermediate(certc.CertOpts{})
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return s.runDirect(ctx, intCert)
	})

	g.Go(func() error {
		for bind, addr := range s.client.destinations {
			if err := s.registerDestination(ctx, bind, addr, intCert); err != nil {
				return err
			}
		}
		return s.runDestinations(ctx)
	})

	for addr, bind := range s.client.sources {
		g.Go(func() error {
			src := &clientSource{
				sess:         s,
				localAddr:    addr,
				destination:  bind,
				logger:       s.logger.With("addr", addr, "bind", bind),
				defaultRoute: s.conn,
			}
			return src.run(ctx)
		})
	}

	return g.Wait()
}

func (s *clientSession) registerDestination(ctx context.Context, bind Binding, addr string, parent *certc.Cert) error {
	destCert, err := parent.NewClient(certc.CertOpts{Domains: []string{"connet-direct"}})
	if err != nil {
		return kleverr.Ret(err)
	}
	cert, err := pb.NewCert(destCert, parent)
	if err != nil {
		return kleverr.Ret(err)
	}

	cmdStream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer cmdStream.Close()

	if err := pb.Write(cmdStream, &pbs.Request{
		Register: &pbs.Request_Register{
			Binding: bind.AsPB(),
			Direct:  s.directAddrs,
			Cert:    cert,
		},
	}); err != nil {
		return kleverr.Ret(err)
	}

	if _, err := pbs.ReadResponse(cmdStream); err != nil {
		return kleverr.Ret(err)
	}

	s.logger.Info("registered destination", "bind", bind, "addr", addr)
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
		s.destinationConnect(ctx, stream, NewBindingPB(req.Connect.Binding))
	default:
		s.unknown(ctx, stream, req)
	}
}

func (s *clientSession) destinationConnect(ctx context.Context, stream quic.Stream, bind Binding) {
	logger := s.logger.With("bind", bind)
	addr, ok := s.client.destinations[bind]
	if !ok {
		err := pb.NewError(pb.Error_DestinationNotFound, "%s not found on this client", bind)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			logger.Warn("could not write response", "addr", addr, "err", err)
		}
		return
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		err := pb.NewError(pb.Error_DestinationDialFailed, "%s could not be dialed: %v", bind, err)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			logger.Warn("could not write response", "addr", addr, "err", err)
		}
		return
	}
	defer conn.Close()

	if err := pb.Write(stream, &pbc.Response{}); err != nil {
		logger.Warn("could not write response", "addr", addr, "err", err)
		return
	}

	logger.Debug("joining from server")
	err = netc.Join(ctx, stream, conn)
	logger.Debug("disconnected from server", "err", err)
}

func (s *clientSession) unknown(ctx context.Context, stream quic.Stream, req *pbc.Request) {
	s.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
		s.logger.Warn("could not write response", "err", err)
	}
}

func (c *clientSession) runDirect(ctx context.Context, parentCert *certc.Cert) error {
	serverCert, err := parentCert.NewServer(certc.CertOpts{Domains: []string{"connet-direct"}})
	if err != nil {
		return err
	}
	localCert, err := serverCert.TLSCert()
	if err != nil {
		return err
	}
	clientCAs, err := parentCert.CertPool()
	if err != nil {
		return err
	}

	l, err := c.transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{localCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"connet-direct"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return err
	}

	c.logger.Debug("listening for direct conns")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			return err
		}
		c.logger.Debug("accepted direct conn", "remote", conn.RemoteAddr())

		go func() {
			defer conn.CloseWithError(0, "done")

			for {
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				c.logger.Debug("serving direct conn", "remote", conn.RemoteAddr())
				go c.runDestinationRequest(ctx, stream)
			}
		}()
	}
}

type clientSource struct {
	sess        *clientSession
	localAddr   string
	destination Binding
	logger      *slog.Logger

	defaultRoute quic.Connection
	routes       []quic.Connection
	routesMu     sync.RWMutex
}

func (s *clientSource) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx) // TODO reliable.Group
	g.Go(func() error {
		return s.runServer(ctx)
	})
	g.Go(func() error {
		return s.runRoutes(ctx)
	})
	return g.Wait()
}

func (s *clientSource) runServer(ctx context.Context) error {
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

func (s *clientSource) runRoutes(ctx context.Context) error {
	for {
		origins, cert, pool, err := s.loadRoutes(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			s.logger.Warn("could not load routes", "err", err)
			time.Sleep(10 * time.Second) // TODO reliable sleep
			continue
		}

		var routes []quic.Connection
		for _, origin := range origins {
			conn, err := s.connectRoute(ctx, origin, cert, pool)
			if err != nil {
				s.logger.Debug("direct route dial failed", "err", err)
				// TODO logging?
				continue
			}

			routes = append(routes, conn)
		}

		s.routesMu.Lock()
		s.routes = routes
		s.routesMu.Unlock()

		time.Sleep(time.Minute) // TODO reliable sleep
	}
}

func (s *clientSource) loadRoutes(ctx context.Context) ([]netip.AddrPort, tls.Certificate, *x509.CertPool, error) {
	stream, err := s.defaultRoute.OpenStreamSync(ctx)
	if err != nil {
		s.logger.Warn("failed to open server stream", "err", err)
		return nil, tls.Certificate{}, nil, err
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		Routes: &pbs.Request_Routes{
			Binding: s.destination.AsPB(),
		},
	}); err != nil {
		s.logger.Warn("failed to request routes", "err", err)
		return nil, tls.Certificate{}, nil, err
	}

	resp, err := pbs.ReadResponse(stream)
	if err != nil {
		s.logger.Warn("failed to response connection", "err", err)
		return nil, tls.Certificate{}, nil, err
	}

	var result []netip.AddrPort
	for _, addr := range resp.Routes.Direct {
		result = append(result, addr.AsNetip())
	}
	s.logger.Info("routes addresses", "addrs", result)

	cert, err := tls.X509KeyPair(resp.Routes.Cert.Der, resp.Routes.Cert.Pkey)
	if err != nil {
		s.logger.Warn("failed to parse pair", "err", err)
		return nil, tls.Certificate{}, nil, err
	}

	caData, _ := pem.Decode(resp.Routes.Cert.Cas[0])
	if caData == nil || caData.Type != "CERTIFICATE" {
		return nil, tls.Certificate{}, nil, kleverr.New("failed to decode pem")
	}
	caCert, err := x509.ParseCertificate(caData.Bytes) // TODO
	if err != nil {
		s.logger.Warn("failed to parse ca", "err", err)
		return nil, tls.Certificate{}, nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return result, cert, pool, nil
}

func (s *clientSource) connectRoute(ctx context.Context, addr netip.AddrPort, cert tls.Certificate, caPool *x509.CertPool) (quic.Connection, error) {
	// TODO do not redial every time
	// TODO share certs
	return s.sess.transport.Dial(ctx, net.UDPAddrFromAddrPort(addr), &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   cert.Leaf.DNSNames[0],
		NextProtos:   []string{"connet-direct"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
}

func (s *clientSource) openRoute(ctx context.Context) (quic.Stream, bool, error) {
	s.routesMu.RLock()
	routes := s.routes
	s.routesMu.RUnlock()

	for _, route := range routes {
		if stream, err := route.OpenStreamSync(ctx); err == nil {
			return stream, true, nil
		}
	}
	if stream, err := s.defaultRoute.OpenStreamSync(ctx); err != nil {
		return nil, false, err
	} else {
		return stream, false, nil
	}
}

func (s *clientSource) runConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	s.logger.Debug("received conn", "remote", conn.RemoteAddr())
	stream, direct, err := s.openRoute(ctx)
	if err != nil {
		s.logger.Warn("failed to open server stream", "err", err)
		return
	}
	defer stream.Close()

	if direct {
		if err := pb.Write(stream, &pbc.Request{
			Connect: &pbc.Request_Connect{
				Binding: s.destination.AsPB(),
			},
		}); err != nil {
			s.logger.Warn("failed to request connection", "err", err)
			return
		}

		resp, err := pbc.ReadResponse(stream)
		if err != nil {
			s.logger.Warn("failed to response connection", "err", err)
			return
		}

		s.logger.Debug("joining to client", "connect", resp)
	} else {
		if err := pb.Write(stream, &pbs.Request{
			Connect: &pbs.Request_Connect{
				Binding: s.destination.AsPB(),
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

		s.logger.Debug("joining to server", "connect", resp.Connect)
	}

	err = netc.Join(ctx, conn, stream)
	s.logger.Debug("disconnected to server", "err", err)
}

type clientConfig struct {
	serverAddr   *net.UDPAddr
	serverName   string
	directAddr   *net.UDPAddr
	token        string
	sources      map[string]Binding
	destinations map[Binding]string
	cas          *x509.CertPool
	logger       *slog.Logger
}

type ClientOption func(cfg *clientConfig) error

func ClientServerAddress(address string) ClientOption {
	return func(cfg *clientConfig) error {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		cfg.serverAddr = addr
		cfg.serverName = host
		return nil
	}
}

func ClientDirectAddress(address string) ClientOption {
	return func(cfg *clientConfig) error {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return err
		}
		cfg.directAddr = addr
		return nil
	}
}

func ClientAuthentication(token string) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.token = token
		return nil
	}
}

func ClientGlobalSource(addr, name string) ClientOption {
	return ClientSource(addr, "", name)
}

func ClientSource(addr, realm, name string) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.sources == nil {
			cfg.sources = map[string]Binding{}
		}
		cfg.sources[addr] = Binding{Realm: realm, Name: name}
		return nil
	}
}

func ClientGlobalDestination(name, addr string) ClientOption {
	return ClientDestination("", name, addr)
}

func ClientDestination(realm, name, addr string) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.destinations == nil {
			cfg.destinations = map[Binding]string{}
		}
		cfg.destinations[Binding{Realm: realm, Name: name}] = addr
		return nil
	}
}

func ClientCA(certFile string, keyFile string) ClientOption {
	return func(cfg *clientConfig) error {
		if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return err
		} else {
			pool := x509.NewCertPool()
			pool.AddCert(cert.Leaf)
			cfg.cas = pool
			return nil
		}
	}
}

func ClientLogger(logger *slog.Logger) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.logger = logger
		return nil
	}
}

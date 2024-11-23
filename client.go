package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type Client struct {
	clientConfig

	serverCert tls.Certificate
	clientCert tls.Certificate
	dialer     *destinationsDialer

	directServer  *clientDirectServer
	sourceServers map[Binding]*clientSourceServer
}

func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := &clientConfig{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, kleverr.Ret(err)
		}
	}

	if cfg.serverAddr == nil {
		if err := ClientServerAddress("127.0.0.1:19190")(cfg); err != nil {
			return nil, kleverr.Ret(err)
		}
	}

	if cfg.directAddr == nil {
		if err := ClientDirectAddress("0.0.0.0:19192")(cfg); err != nil {
			return nil, kleverr.Ret(err)
		}
	}

	rootCert, err := certc.NewRoot()
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	cfg.logger.Debug("generated root cert")

	serverCert, err := rootCert.NewServer(certc.CertOpts{
		Domains: []string{"connet-direct"},
	})
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	serverTLSCert, err := serverCert.TLSCert()
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	cfg.logger.Debug("generated server cert")

	clientCert, err := rootCert.NewClient(certc.CertOpts{})
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	clientTLSCert, err := clientCert.TLSCert()
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	cfg.logger.Debug("generated client cert")

	return &Client{
		clientConfig: *cfg,

		serverCert: serverTLSCert,
		clientCert: clientTLSCert,
		dialer: &destinationsDialer{
			destinations: cfg.destinations,
			logger:       cfg.logger.With("component", "dialer"),
		},

		sourceServers: map[Binding]*clientSourceServer{},
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	directUDP, err := net.ListenUDP("udp", c.directAddr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer directUDP.Close()

	directTransport := &quic.Transport{
		Conn: directUDP,
		// TODO review other options
	}

	c.directServer = &clientDirectServer{
		dialer:     c.dialer,
		transport:  directTransport,
		serverCert: c.serverCert,
		logger:     c.logger.With("component", "direct-server", "addr", c.directAddr),
	}

	for addr, bind := range c.sources {
		c.sourceServers[bind] = &clientSourceServer{
			addr:      addr,
			bind:      bind,
			transport: directTransport,
			cert:      c.clientCert,
			relayCAs:  c.controlCAs,
			logger:    c.logger.With("component", "source-server", "addr", addr, "bind", bind),
		}
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return c.directServer.run(ctx) })

	for _, srv := range c.sourceServers {
		g.Go(func() error { return srv.run(ctx) })
	}

	g.Go(func() error { return c.run(ctx, directTransport) })

	return g.Wait()
}

func (c *Client) run(ctx context.Context, transport *quic.Transport) error {
	sess, err := c.connect(ctx, transport)
	if err != nil {
		return err
	}

	for {
		if err := sess.run(ctx); err != nil {
			c.logger.Error("session ended", "err", err)
			return err
		}

		if sess, err = c.reconnect(ctx, transport); err != nil {
			return err
		}
	}
}

func (c *Client) connect(ctx context.Context, transport *quic.Transport) (*clientSession, error) {
	c.logger.Debug("dialing target", "addr", c.serverAddr)
	// TODO dial timeout if server is not accessible?
	conn, err := transport.Dial(ctx, c.serverAddr, &tls.Config{
		ServerName: c.serverName,
		RootCAs:    c.controlCAs,
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
		client:           c,
		id:               sid,
		transport:        transport,
		conn:             conn,
		directAddrs:      []*pb.AddrPort{resp.Public},
		relayAddrsNotify: newNotify(),
		activeRelays:     map[string]*clientRelayServer{},
		logger:           c.logger.With("connection-id", sid),
	}, nil
}

func (c *Client) reconnect(ctx context.Context, transport *quic.Transport) (*clientSession, error) {
	for {
		time.Sleep(time.Second) // TODO backoff and such

		if sess, err := c.connect(ctx, transport); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return sess, nil
		}
	}
}

type clientSession struct {
	client           *Client
	id               ksuid.KSUID
	transport        *quic.Transport
	conn             quic.Connection
	directAddrs      []*pb.AddrPort // TODO these should be multiple, not only from server pov
	relayAddrs       map[string]struct{}
	relayAddrsMu     sync.RWMutex
	relayAddrsNotify *notify
	activeRelays     map[string]*clientRelayServer
	logger           *slog.Logger
}

func (s *clientSession) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runRelays(ctx) })
	g.Go(func() error { return s.runRelayConns(ctx) })

	for dst := range s.client.destinations {
		g.Go(func() error { return s.runDestination(ctx, dst) })
	}

	for _, src := range s.client.sources {
		g.Go(func() error { return s.runSource(ctx, src) })
	}

	return g.Wait()
}

func (s *clientSession) runRelays(ctx context.Context) error {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		Relay: &pbs.Request_Relay{
			Certificate:  s.client.clientCert.Leaf.Raw,
			Destinations: AsPBBindings(slices.Collect(maps.Keys(s.client.destinations))),
			Sources:      AsPBBindings(slices.Collect(maps.Values(s.client.sources))),
		},
	}); err != nil {
		return err
	}

	for {
		resp, err := pbs.ReadResponse(stream)
		if err != nil {
			return err
		}
		if resp.Relay == nil {
			return kleverr.Newf("unexpected response")
		}

		addrs := map[string]struct{}{}
		for _, addr := range resp.Relay.Relays {
			addrs[addr.Hostport] = struct{}{}
		}
		s.setRelayAddrs(ctx, addrs)
	}
}

func (s *clientSession) runRelayConns(ctx context.Context) error {
	defer s.logger.Debug("completed relays notify")
	return runNotify(ctx, s.relayAddrsNotify, func() error {
		relays := s.getRelayAddrs()
		s.logger.Debug("updated relays", "relays", len(relays))
		for _, addr := range s.getRelayAddrs() {
			if _, ok := s.activeRelays[addr.Hostport]; ok {
				continue
			}

			srv := &clientRelayServer{
				hostport:  addr.Hostport,
				transport: s.transport,
				cert:      s.client.clientCert,
				relayCAs:  s.client.controlCAs,
				dialer:    s.client.dialer,
				logger:    s.client.logger.With("component", "relay", "addr", addr.Hostport),
			}
			s.activeRelays[addr.Hostport] = srv
			go srv.run(ctx)
		}
		return nil
	})
}

func (s *clientSession) setRelayAddrs(ctx context.Context, addrs map[string]struct{}) {
	defer s.relayAddrsNotify.inc()

	s.relayAddrsMu.Lock()
	defer s.relayAddrsMu.Unlock()

	s.relayAddrs = maps.Clone(addrs)
}

func (s *clientSession) getDirectAddr() []*pbs.Route {
	var directs []*pbs.Route
	for _, direct := range s.directAddrs {
		directs = append(directs, &pbs.Route{
			Hostport:    direct.AsNetip().String(),
			Certificate: s.client.serverCert.Leaf.Raw,
		})
	}

	return directs
}

func (s *clientSession) getRelayAddrs() []*pbs.Route {
	s.relayAddrsMu.RLock()
	defer s.relayAddrsMu.RUnlock()

	var relays []*pbs.Route
	for hostport := range s.relayAddrs {
		relays = append(relays, &pbs.Route{
			Hostport: hostport,
		})
	}

	return relays
}

func (s *clientSession) runDestination(ctx context.Context, bind Binding) error {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		Destination: &pbs.Request_Destination{
			Binding: bind.AsPB(),
			Directs: s.getDirectAddr(),
			Relays:  s.getRelayAddrs(),
		},
	}); err != nil {
		return kleverr.Ret(err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer s.logger.Debug("completed destinations notify")
		return runNotify(ctx, s.relayAddrsNotify, func() error {
			direct, relays := s.getDirectAddr(), s.getRelayAddrs()
			s.logger.Debug("updated destinations", "direct", len(direct), "relays", len(relays))
			if err := pb.Write(stream, &pbs.Request{
				Destination: &pbs.Request_Destination{
					Binding: bind.AsPB(),
					Directs: s.getDirectAddr(),
					Relays:  s.getRelayAddrs(),
				},
			}); err != nil {
				return kleverr.Ret(err)
			}
			return nil
		})
	})

	g.Go(func() error {
		for {
			resp, err := pbs.ReadResponse(stream)
			if err != nil {
				return err
			}
			if resp.Destination == nil {
				return kleverr.Newf("unexpected response")
			}

			pool := x509.NewCertPool()
			for _, certData := range resp.Destination.Certificates {
				if cert, err := x509.ParseCertificate(certData); err != nil {
					return kleverr.Newf("failed to parse cert: %w", err)
				} else {
					pool.AddCert(cert)
				}
			}
			s.client.directServer.clientCA.Store(pool)
		}
	})

	return g.Wait()
}

func (s *clientSession) runSource(ctx context.Context, bind Binding) error {
	srcServer := s.client.sourceServers[bind]

	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		Source: &pbs.Request_Source{
			Binding:     bind.AsPB(),
			Certificate: s.client.clientCert.Leaf.Raw,
		},
	}); err != nil {
		return kleverr.Ret(err)
	}

	for {
		resp, err := pbs.ReadResponse(stream)
		if err != nil {
			return err
		}
		if resp.Source == nil {
			return kleverr.Newf("unexpected response")
		}

		directs := map[string]*x509.Certificate{}
		for _, direct := range resp.Source.Directs {
			cert, err := x509.ParseCertificate(direct.Certificate)
			if err != nil {
				s.logger.Warn("invalid certificate", "err", err)
				continue
			}
			directs[direct.Hostport] = cert
		}

		relays := map[string]struct{}{}
		for _, relay := range resp.Source.Relays {
			relays[relay.Hostport] = struct{}{}
		}

		srcServer.setRoutes(directs, relays)
	}
}

type clientConfig struct {
	serverAddr   *net.UDPAddr
	serverName   string
	directAddr   *net.UDPAddr
	token        string
	sources      map[string]Binding
	destinations map[Binding]string
	controlCAs   *x509.CertPool
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
			cfg.controlCAs = pool
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

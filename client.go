package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
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
	sourceServers map[model.Forward]*clientSourceServer
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

	if cfg.controlAddr == nil {
		if err := ClientControlAddress("127.0.0.1:19190")(cfg); err != nil {
			return nil, kleverr.Ret(err)
		}
	}

	if cfg.directAddr == nil {
		if err := ClientDirectAddress(":19192")(cfg); err != nil {
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

		sourceServers: map[model.Forward]*clientSourceServer{},
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

	for src, cfg := range c.sources {
		c.sourceServers[src] = &clientSourceServer{
			addr:      cfg.addr,
			fwd:       src,
			transport: directTransport,
			cert:      c.clientCert,
			logger:    c.logger.With("component", "source-server", "forward", src, "addr", cfg.addr),
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
			switch {
			case errors.Is(err, context.Canceled):
				return err
				// TODO other terminal errors
			}
		}

		if sess, err = c.reconnect(ctx, transport); err != nil {
			return err
		}
	}
}

func (c *Client) connect(ctx context.Context, transport *quic.Transport) (*clientSession, error) {
	c.logger.Debug("dialing target", "addr", c.controlAddr)
	// TODO dial timeout if server is not accessible?
	conn, err := transport.Dial(ctx, c.controlAddr, &tls.Config{
		ServerName: c.controlHost,
		RootCAs:    c.controlCAs,
		NextProtos: []string{"connet"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return nil, kleverr.Ret(err)
	}

	c.logger.Debug("authenticating", "addr", c.controlAddr)

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
		relayAddrsNotify: notify.New(),
		activeRelays:     map[string]*clientRelayServer{},
		logger:           c.logger.With("connection-id", sid),
	}, nil
}

func (c *Client) reconnect(ctx context.Context, transport *quic.Transport) (*clientSession, error) {
	d := 10 * time.Millisecond
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		c.logger.Debug("backoff wait", "d", d)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}

		if sess, err := c.connect(ctx, transport); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return sess, nil
		}

		d = jitterBackoff(d, 10*time.Millisecond, 15*time.Second)
		t.Reset(d)
	}
}

func jitterBackoff(d, jmin, jmax time.Duration) time.Duration {
	dt := int64(d*3 - jmin)
	nd := jmin + time.Duration(rand.Int64N(dt))
	return min(jmax, nd)
}

type clientSession struct {
	client           *Client
	id               ksuid.KSUID
	transport        *quic.Transport
	conn             quic.Connection
	directAddrs      []*pb.AddrPort // TODO these should be multiple, not only from server pov
	relayAddrs       map[string]*x509.Certificate
	relayAddrsMu     sync.RWMutex
	relayAddrsNotify *notify.N
	activeRelays     map[string]*clientRelayServer
	logger           *slog.Logger
}

func (s *clientSession) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.runRelays(ctx) })
	g.Go(func() error { return s.runRelayConns(ctx) })

	for dst, cfg := range s.client.destinations {
		g.Go(func() error { return s.runDestination(ctx, dst, cfg.route) })
	}

	for src, cfg := range s.client.sources {
		g.Go(func() error { return s.runSource(ctx, src, cfg.route) })
	}

	return g.Wait()
}

func (s *clientSession) runRelays(ctx context.Context) error {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	var dsts []model.Forward
	for fwd, cfg := range s.client.destinations {
		if cfg.route.AllowRelay() {
			dsts = append(dsts, fwd)
		}
	}

	var srcs []model.Forward
	for fwd, cfg := range s.client.sources {
		if cfg.route.AllowRelay() {
			srcs = append(srcs, fwd)
		}
	}

	if err := pb.Write(stream, &pbs.Request{
		Relay: &pbs.Request_Relay{
			Certificate:  s.client.clientCert.Leaf.Raw,
			Destinations: model.PBFromForwards(dsts),
			Sources:      model.PBFromForwards(srcs),
		},
	}); err != nil {
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
			resp, err := pbs.ReadResponse(stream)
			if err != nil {
				return err
			}
			if resp.Relay == nil {
				return kleverr.Newf("unexpected response")
			}

			addrs := map[string]*x509.Certificate{}
			for _, relay := range resp.Relay.Relays {
				route, err := model.NewRouteFromPB(relay)
				if err != nil {
					s.logger.Warn("cannot parse route", "err", err)
					continue
				}
				addrs[route.Hostport] = route.Certificate
			}
			s.setRelayAddrs(addrs)
		}
	})

	return g.Wait()
}

func (s *clientSession) runRelayConns(ctx context.Context) error {
	defer s.logger.Debug("completed relays notify")
	return s.relayAddrsNotify.Listen(ctx, func() error {
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

func (s *clientSession) setRelayAddrs(addrs map[string]*x509.Certificate) {
	defer s.relayAddrsNotify.Updated()

	s.relayAddrsMu.Lock()
	defer s.relayAddrsMu.Unlock()

	s.relayAddrs = maps.Clone(addrs)
}

func (s *clientSession) getDirectAddrs() []*pbs.Route {
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
	for hostport, cert := range s.relayAddrs {
		var certData []byte
		if cert != nil {
			certData = cert.Raw
		}
		relays = append(relays, &pbs.Route{
			Hostport:    hostport,
			Certificate: certData,
		})
	}

	return relays
}

func (s *clientSession) runDestination(ctx context.Context, fwd model.Forward, opt model.RouteOption) error {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	dstReq := &pbs.Request_Destination{From: fwd.PB()}
	if opt.AllowDirect() {
		dstReq.Directs = s.getDirectAddrs()
	}
	if opt.AllowRelay() {
		dstReq.Relays = s.getRelayAddrs()
	}

	if err := pb.Write(stream, &pbs.Request{
		Destination: dstReq,
	}); err != nil {
		return kleverr.Ret(err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	})

	g.Go(func() error {
		defer s.logger.Debug("completed destinations notify")
		return s.relayAddrsNotify.Listen(ctx, func() error {
			dstReq := &pbs.Request_Destination{From: fwd.PB()}
			if opt.AllowDirect() {
				dstReq.Directs = s.getDirectAddrs()
			}
			if opt.AllowRelay() {
				dstReq.Relays = s.getRelayAddrs()
			}
			s.logger.Debug("updated destinations", "direct", len(dstReq.Directs), "relays", len(dstReq.Relays))
			if err := pb.Write(stream, &pbs.Request{
				Destination: dstReq,
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

func (s *clientSession) runSource(ctx context.Context, fwd model.Forward, opt model.RouteOption) error {
	srcServer := s.client.sourceServers[fwd]

	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbs.Request{
		Source: &pbs.Request_Source{
			To:          fwd.PB(),
			Certificate: s.client.clientCert.Leaf.Raw,
		},
	}); err != nil {
		return kleverr.Ret(err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	})

	g.Go(func() error {
		for {
			resp, err := pbs.ReadResponse(stream)
			if err != nil {
				return err
			}
			if resp.Source == nil {
				return kleverr.Newf("unexpected response")
			}

			directs := map[string]*x509.Certificate{}
			if opt.AllowDirect() {
				for _, direct := range resp.Source.Directs {
					route, err := model.NewRouteFromPB(direct)
					if err != nil {
						s.logger.Warn("cannot parse route", "err", err)
						continue
					}
					directs[route.Hostport] = route.Certificate
				}
			}

			relays := map[string]*x509.Certificate{}
			if opt.AllowRelay() {
				for _, relay := range resp.Source.Relays {
					route, err := model.NewRouteFromPB(relay)
					if err != nil {
						s.logger.Warn("cannot parse route", "err", err)
						continue
					}
					relays[route.Hostport] = route.Certificate
				}
			}

			srcServer.setRoutes(directs, relays)
		}
	})

	return g.Wait()
}

type clientConfig struct {
	token string

	controlAddr *net.UDPAddr
	controlHost string
	controlCAs  *x509.CertPool

	directAddr *net.UDPAddr

	destinations map[model.Forward]clientForwardConfig
	sources      map[model.Forward]clientForwardConfig

	logger *slog.Logger
}

type clientForwardConfig struct {
	addr  string
	route model.RouteOption
}

type ClientOption func(cfg *clientConfig) error

func ClientToken(token string) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.token = token
		return nil
	}
}

func ClientControlAddress(address string) ClientOption {
	return func(cfg *clientConfig) error {
		if i := strings.LastIndex(address, ":"); i < 0 {
			// missing :port, lets give it the default
			address = fmt.Sprintf("%s:%d", address, 19190)
		}
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}

		cfg.controlAddr = addr
		cfg.controlHost = host

		return nil
	}
}

func ClientControlCAs(certFile string) ClientOption {
	return func(cfg *clientConfig) error {
		casData, err := os.ReadFile(certFile)
		if err != nil {
			return kleverr.Newf("cannot read certs file: %w", err)
		}

		cas := x509.NewCertPool()
		if !cas.AppendCertsFromPEM(casData) {
			return kleverr.Newf("no certificates found in %s", certFile)
		}

		cfg.controlCAs = cas

		return nil
	}
}

func clientControlCAs(cas *x509.CertPool) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.controlCAs = cas

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

func ClientDestination(name, addr string, route model.RouteOption) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.destinations == nil {
			cfg.destinations = map[model.Forward]clientForwardConfig{}
		}
		cfg.destinations[model.NewForward(name)] = clientForwardConfig{addr, route}
		return nil
	}
}

func ClientSource(name, addr string, route model.RouteOption) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.sources == nil {
			cfg.sources = map[model.Forward]clientForwardConfig{}
		}
		cfg.sources[model.NewForward(name)] = clientForwardConfig{addr, route}
		return nil
	}
}

func ClientLogger(logger *slog.Logger) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.logger = logger
		return nil
	}
}

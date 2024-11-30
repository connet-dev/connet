package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/client"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Client struct {
	clientConfig

	rootCert *certc.Cert
	dsts     map[model.Forward]*client.Destination
	srcs     map[model.Forward]*client.Source
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

	return &Client{
		clientConfig: *cfg,

		rootCert: rootCert,
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

	ds := client.NewDirectServer(directTransport, c.logger)

	c.dsts = map[model.Forward]*client.Destination{}
	for fwd, cfg := range c.destinations {
		c.dsts[fwd], err = client.NewDestination(fwd, cfg.addr, cfg.route, ds, c.rootCert, c.logger)
		if err != nil {
			return kleverr.Ret(err)
		}
	}

	c.srcs = map[model.Forward]*client.Source{}
	for fwd, cfg := range c.sources {
		c.srcs[fwd], err = client.NewSource(fwd, cfg.addr, cfg.route, ds, c.rootCert, c.logger)
		if err != nil {
			return kleverr.Ret(err)
		}
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return ds.Run(ctx) })

	for _, dst := range c.dsts {
		g.Go(func() error { return dst.Run(ctx) })
	}

	for _, src := range c.srcs {
		g.Go(func() error { return src.Run(ctx) })
	}

	g.Go(func() error { return c.run(ctx, directTransport) })

	return g.Wait()
}

func (c *Client) run(ctx context.Context, transport *quic.Transport) error {
	conn, err := c.connect(ctx, transport)
	if err != nil {
		return err
	}

	for {
		if err := c.runConnection(ctx, conn); err != nil {
			c.logger.Error("session ended", "err", err)
			switch {
			case errors.Is(err, context.Canceled):
				return err
				// TODO other terminal errors
			}
		}

		if conn, err = c.reconnect(ctx, transport); err != nil {
			return err
		}
	}
}

func (c *Client) connect(ctx context.Context, transport *quic.Transport) (quic.Connection, error) {
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

	localAddrs, err := netc.LocalAddrs()
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	localAddrPorts := make([]netip.AddrPort, len(localAddrs))
	for i, addr := range localAddrs {
		localAddrPorts[i] = netip.AddrPortFrom(addr, c.clientConfig.directAddr.AddrPort().Port())
	}

	// directAddrs := append(localAddrPorts, resp.Public.AsNetip())
	directAddrs := []netip.AddrPort{resp.Public.AsNetip()} // TODO revert
	for _, d := range c.dsts {
		d.SetDirectAddrs(directAddrs)
	}
	for _, s := range c.srcs {
		s.SetDirectAddrs(directAddrs)
	}

	c.logger.Info("authenticated", "addrs", directAddrs)
	return conn, nil
}

func (c *Client) runConnection(ctx context.Context, conn quic.Connection) error {
	g, ctx := errgroup.WithContext(ctx)

	for _, dstServer := range c.dsts {
		g.Go(func() error { return dstServer.RunControl(ctx, conn) })
	}

	for _, srcServer := range c.srcs {
		g.Go(func() error { return srcServer.RunControl(ctx, conn) })
	}

	return g.Wait()
}

func (c *Client) reconnect(ctx context.Context, transport *quic.Transport) (quic.Connection, error) {
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

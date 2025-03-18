package connet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/client"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbs"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/statusc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Client struct {
	clientConfig

	rootCert *certc.Cert
	dsts     map[model.Forward]*client.Destination
	srcs     map[model.Forward]*client.Source

	connStatus atomic.Value
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

	if cfg.controlAddr == nil {
		if err := ClientControlAddress("127.0.0.1:19190")(cfg); err != nil {
			return nil, fmt.Errorf("default control address: %w", err)
		}
	}

	if cfg.directAddr == nil {
		if err := ClientDirectAddress(":19192")(cfg); err != nil {
			return nil, fmt.Errorf("default direct address: %w", err)
		}
	}

	if cfg.directResetKey == nil {
		if err := clientDirectStatelessResetKey()(cfg); err != nil {
			return nil, fmt.Errorf("default stateless reset key: %w", err)
		}
		if cfg.directResetKey == nil {
			cfg.logger.Warn("running without a stateless reset key")
		}
	}

	if len(cfg.destinations) == 0 && len(cfg.sources) == 0 {
		// TODO fix this
		return nil, fmt.Errorf("missing destination or source")
	}

	rootCert, err := certc.NewRoot()
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}
	cfg.logger.Debug("generated root cert")

	c := &Client{
		clientConfig: *cfg,

		rootCert: rootCert,
	}
	c.connStatus.Store(statusc.NotConnected)

	return c, nil
}

func (c *Client) Run(ctx context.Context) error {
	c.logger.Debug("start udp listener")
	udpConn, err := net.ListenUDP("udp", c.directAddr)
	if err != nil {
		return fmt.Errorf("listen direct address: %w", err)
	}
	defer udpConn.Close()

	c.logger.Debug("start quic listener")
	transport := quicc.ClientTransport(udpConn, c.directResetKey)
	defer transport.Close()

	ds, err := client.NewDirectServer(transport, c.logger)
	if err != nil {
		return fmt.Errorf("create direct server: %w", err)
	}

	c.dsts = map[model.Forward]*client.Destination{}
	for fwd, cfg := range c.destinations {
		c.dsts[fwd], err = client.NewDestination(cfg, ds, c.rootCert, c.logger)
		if err != nil {
			return fmt.Errorf("create destination %s: %w", fwd, err)
		}
	}

	c.srcs = map[model.Forward]*client.Source{}
	for fwd, cfg := range c.sources {
		c.srcs[fwd], err = client.NewSource(cfg, ds, c.rootCert, c.logger)
		if err != nil {
			return fmt.Errorf("client source %s: %w", fwd, err)
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

	g.Go(func() error { return c.run(ctx, transport) })
	g.Go(func() error { return c.runStatus(ctx) })

	return g.Wait()
}

func (c *Client) run(ctx context.Context, transport *quic.Transport) error {
	conn, retoken, err := c.connect(ctx, transport, nil)
	if err != nil {
		return err
	}

	for {
		if err := c.runConnection(ctx, conn); err != nil {
			switch {
			case errors.Is(err, context.Canceled):
				return err
				// TODO other terminal errors
			}
			if perr := pb.GetError(err); perr != nil && perr.IsAuthenticationError() {
				return err
			}
			c.logger.Error("session ended", "err", err)
		}

		if conn, retoken, err = c.reconnect(ctx, transport, retoken); err != nil {
			return err
		}
	}
}

func (c *Client) connect(ctx context.Context, transport *quic.Transport, retoken []byte) (quic.Connection, []byte, error) {
	c.logger.Debug("dialing target", "addr", c.controlAddr)
	// TODO dial timeout if server is not accessible?
	conn, err := transport.Dial(quicc.RTTContext(ctx), c.controlAddr, &tls.Config{
		ServerName: c.controlHost,
		RootCAs:    c.controlCAs,
		NextProtos: []string{"connet"},
	}, quicc.StdConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("dial server: %w", err)
	}

	c.logger.Debug("authenticating", "addr", c.controlAddr)

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("open authentication stream: %w", err)
	}
	defer authStream.Close()

	if err := pb.Write(authStream, &pbs.Authenticate{
		Token:          c.token,
		ReconnectToken: retoken,
	}); err != nil {
		return nil, nil, fmt.Errorf("write authentication: %w", err)
	}

	resp := &pbs.AuthenticateResp{}
	if err := pb.Read(authStream, resp); err != nil {
		return nil, nil, fmt.Errorf("authentication read failed: %w", err)
	}
	if resp.Error != nil {
		return nil, nil, fmt.Errorf("authentication failed: %w", resp.Error)
	}

	localAddrs, err := netc.LocalAddrs()
	if err != nil {
		return nil, nil, fmt.Errorf("local addrs: %w", err)
	}
	localAddrPorts := make([]netip.AddrPort, len(localAddrs))
	for i, addr := range localAddrs {
		localAddrPorts[i] = netip.AddrPortFrom(addr, c.clientConfig.directAddr.AddrPort().Port())
	}

	directAddrs := append(localAddrPorts, resp.Public.AsNetip())
	for _, d := range c.dsts {
		d.SetDirectAddrs(directAddrs)
	}
	for _, s := range c.srcs {
		s.SetDirectAddrs(directAddrs)
	}

	c.logger.Info("authenticated to server", "addr", c.controlAddr, "direct", directAddrs)
	return conn, resp.ReconnectToken, nil
}

func (c *Client) reconnect(ctx context.Context, transport *quic.Transport, retoken []byte) (quic.Connection, []byte, error) {
	d := netc.MinBackoff
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		c.logger.Debug("backoff wait", "d", d)
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-t.C:
		}

		if sess, retoken, err := c.connect(ctx, transport, retoken); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return sess, retoken, nil
		}

		d = netc.NextBackoff(d)
		t.Reset(d)
	}
}

func (c *Client) runConnection(ctx context.Context, conn quic.Connection) error {
	defer conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_Unknown), "connection closed")

	c.connStatus.Store(statusc.Connected)
	defer c.connStatus.Store(statusc.Disconnected)

	g, ctx := errgroup.WithContext(ctx)

	for _, dstServer := range c.dsts {
		g.Go(func() error { return dstServer.RunControl(ctx, conn) })
	}

	for _, srcServer := range c.srcs {
		g.Go(func() error { return srcServer.RunControl(ctx, conn) })
	}

	return g.Wait()
}

func (c *Client) runStatus(ctx context.Context) error {
	if c.statusAddr == nil {
		return nil
	}

	c.logger.Debug("running status server", "addr", c.statusAddr)
	return statusc.Run(ctx, c.statusAddr.String(), c.Status)
}

func (c *Client) Status(ctx context.Context) (ClientStatus, error) {
	stat := c.connStatus.Load().(statusc.Status)
	var err error

	dsts := map[model.Forward]client.PeerStatus{}
	for fwd, dst := range c.dsts {
		dsts[fwd], err = dst.Status()
		if err != nil {
			return ClientStatus{}, err
		}
	}

	srcs := map[model.Forward]client.PeerStatus{}
	for fwd, src := range c.srcs {
		srcs[fwd], err = src.Status()
		if err != nil {
			return ClientStatus{}, err
		}
	}

	return ClientStatus{
		Status:       stat,
		Destinations: dsts,
		Sources:      srcs,
	}, nil
}

type ClientStatus struct {
	Status       statusc.Status                      `json:"status"`
	Destinations map[model.Forward]client.PeerStatus `json:"destinations"`
	Sources      map[model.Forward]client.PeerStatus `json:"sources"`
}

type clientConfig struct {
	token string

	controlAddr *net.UDPAddr
	controlHost string
	controlCAs  *x509.CertPool

	directAddr     *net.UDPAddr
	directResetKey *quic.StatelessResetKey
	statusAddr     *net.TCPAddr

	destinations map[model.Forward]client.DestinationConfig
	sources      map[model.Forward]client.SourceConfig

	logger *slog.Logger
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
			return fmt.Errorf("resolve control address: %w", err)
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("split control address: %w", err)
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
			return fmt.Errorf("read server CAs: %w", err)
		}

		cas := x509.NewCertPool()
		if !cas.AppendCertsFromPEM(casData) {
			return fmt.Errorf("missing server CA certificate in %s", certFile)
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
			return fmt.Errorf("resolve direct address: %w", err)
		}

		cfg.directAddr = addr

		return nil
	}
}

func ClientDirectStatelessResetKey(key *quic.StatelessResetKey) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.directResetKey = key
		return nil
	}
}

func ClientDirectStatelessResetKeyFile(path string) ClientOption {
	return func(cfg *clientConfig) error {
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read stateless reset key: %w", err)
		}
		if len(keyBytes) < 32 {
			return fmt.Errorf("stateless reset key len %d", len(keyBytes))
		}

		key := quic.StatelessResetKey(keyBytes)
		cfg.directResetKey = &key

		return nil
	}
}

func clientDirectStatelessResetKey() ClientOption {
	return func(cfg *clientConfig) error {
		var path string

		if cacheDir := os.Getenv("CACHE_DIRECTORY"); cacheDir != "" {
			path = filepath.Join(cacheDir, "client-stateless-reset.key")
		} else if userCacheDir, err := os.UserCacheDir(); err == nil {
			// TODO create connet first
			path = filepath.Join(userCacheDir, "connet", "client-stateless-reset.key")
		} else {
			return nil
		}

		dir := filepath.Dir(path)
		switch _, err := os.Stat(dir); {
		case err == nil:
			// the directory is already there, nothing to do
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(dir, 0600); err != nil {
				return fmt.Errorf("mkdir cache dir: %w", err)
			}
		default:
			return fmt.Errorf("stat cache dir: %w", err)
		}

		switch _, err := os.Stat(path); {
		case err == nil:
			keyBytes, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read stateless reset key: %w", err)
			}
			if len(keyBytes) < 32 {
				return fmt.Errorf("stateless reset key len %d", len(keyBytes))
			}
			key := quic.StatelessResetKey(keyBytes)
			cfg.directResetKey = &key
		case errors.Is(err, os.ErrNotExist):
			var key quic.StatelessResetKey
			if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
				return fmt.Errorf("generate stateless reset key: %w", err)
			}
			if err := os.WriteFile(path, key[:], 0600); err != nil {
				return fmt.Errorf("write stateless reset key: %w", err)
			}
			cfg.directResetKey = &key
		default:
			return fmt.Errorf("stat stateless reset key file: %w", err)
		}

		return nil
	}
}

func ClientStatusAddress(address string) ClientOption {
	return func(cfg *clientConfig) error {
		addr, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			return fmt.Errorf("resolve status address: %w", err)
		}

		cfg.statusAddr = addr

		return nil
	}
}

func ClientDestination(dcfg client.DestinationConfig) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.destinations == nil {
			cfg.destinations = map[model.Forward]client.DestinationConfig{}
		}
		cfg.destinations[dcfg.Forward] = dcfg

		return nil
	}
}

func ClientSource(scfg client.SourceConfig) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.sources == nil {
			cfg.sources = map[model.Forward]client.SourceConfig{}
		}
		cfg.sources[scfg.Forward] = scfg

		return nil
	}
}

func ClientLogger(logger *slog.Logger) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.logger = logger
		return nil
	}
}

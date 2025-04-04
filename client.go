package connet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
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

	rootCert     *certc.Cert
	directServer *client.DirectServer

	dsts map[model.Forward]*client.Destination
	srcs map[model.Forward]*client.Source

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
	c.directServer = ds

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

	return g.Wait()
}

func (c *Client) Destinations() []string {
	return model.ForwardNames(slices.Collect(maps.Keys(c.dsts)))
}

func (c *Client) Destination(name string) (Destination, error) {
	dst, ok := c.dsts[model.NewForward(name)]
	if !ok {
		return nil, fmt.Errorf("destination %s: not found", name)
	}
	return dst, nil
}

func (c *Client) AddDestination(cfg client.DestinationConfig) (Destination, error) {
	dst, err := client.NewDestination(cfg, c.directServer, c.rootCert, c.logger)
	if err != nil {
		return nil, err
	}
	// TODO add to main run group
	// TODO add to current run group
	return dst, nil
}

func (c *Client) Sources() []string {
	return model.ForwardNames(slices.Collect(maps.Keys(c.srcs)))
}

func (c *Client) Source(name string) (Source, error) {
	src, ok := c.srcs[model.NewForward(name)]
	if !ok {
		return nil, fmt.Errorf("source %s: not found", name)
	}
	return src, nil
}

func (c *Client) AddSource(cfg client.SourceConfig) (Source, error) {
	src, err := client.NewSource(cfg, c.directServer, c.rootCert, c.logger)
	if err != nil {
		return nil, err
	}
	// TODO add to main run group
	// TODO add to current run group
	return src, nil
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

type ClientStatus struct {
	Status       statusc.Status                      `json:"status"`
	Destinations map[model.Forward]client.PeerStatus `json:"destinations"`
	Sources      map[model.Forward]client.PeerStatus `json:"sources"`
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

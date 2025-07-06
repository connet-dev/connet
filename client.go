package connet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/client"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/nat"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/slogc"
	"github.com/connet-dev/connet/statusc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Client struct {
	clientConfig

	rootCert     *certc.Cert
	directServer *client.DirectServer

	destinations   map[model.Endpoint]*clientDestination
	destinationsMu sync.RWMutex
	sources        map[model.Endpoint]*clientSource
	sourcesMu      sync.RWMutex

	connStatus     atomic.Value
	currentSession *notify.V[*session]
	ctxCancel      context.CancelCauseFunc
	closer         chan struct{}

	natlocal *nat.Local
	natpmp   *nat.PMP
}

// Connect starts a new client and connects it to the control server.
// This call blocks until the server is connected or an error is detected.
// The client can be stopped either by canceling this context or via calling Close. Stopping the client will also
// stop all active source/destinations associated with this client
func Connect(ctx context.Context, opts ...ClientOption) (*Client, error) {
	cfg, err := newClientConfig(opts)
	if err != nil {
		return nil, err
	}

	rootCert, err := certc.NewRoot()
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}
	cfg.logger.Debug("generated root cert")

	c := &Client{
		clientConfig: *cfg,

		rootCert: rootCert,

		destinations: map[model.Endpoint]*clientDestination{},
		sources:      map[model.Endpoint]*clientSource{},

		currentSession: notify.New[*session](nil),
		closer:         make(chan struct{}),
	}
	c.connStatus.Store(statusc.NotConnected)

	ctx, cancel := context.WithCancelCause(ctx)
	c.ctxCancel = cancel

	errCh := make(chan error)
	go c.runClient(ctx, errCh)

	if err := <-errCh; err != nil {
		cerr := c.Close()
		return nil, errors.Join(err, cerr)
	}

	return c, nil
}

func (c *Client) runClient(ctx context.Context, errCh chan error) {
	defer close(c.closer)
	defer c.connStatus.Store(statusc.Disconnected)
	defer c.closeEndpoints()

	c.logger.Debug("start udp listener")
	udpConn, err := net.ListenUDP("udp", c.directAddr)
	if err != nil {
		errCh <- fmt.Errorf("listen direct address: %w", err)
		return
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			slogc.Fine(c.logger, "error closing udp listener", "err", err)
		}
	}()

	c.logger.Debug("start quic listener")
	transport := quicc.ClientTransport(udpConn, c.directResetKey)
	defer func() {
		if err := transport.Close(); err != nil {
			slogc.Fine(c.logger, "error closing transport", "err", err)
		}
	}()

	ds, err := client.NewDirectServer(transport, c.logger)
	if err != nil {
		errCh <- fmt.Errorf("create direct server: %w", err)
		return
	}
	c.directServer = ds

	c.natlocal = nat.NewLocal(uint16(c.directAddr.Port), c.logger)
	c.natpmp = nat.NewPMP(c.natPMP, transport, uint16(c.directAddr.Port), c.logger)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return ds.Run(ctx) })
	g.Go(func() error { return c.natpmp.Run(ctx) })
	g.Go(func() error { return c.run(ctx, transport, errCh) })

	if err := g.Wait(); err != nil {
		c.logger.Warn("shutting down client", "err", err)
	}
}

// Destinations returns the set of currently active destinations
func (c *Client) Destinations() []string {
	c.destinationsMu.RLock()
	defer c.destinationsMu.RUnlock()

	return model.EndpointNames(slices.Collect(maps.Keys(c.destinations)))
}

// GetDestination returns a destination by its name. Returns an error if the destination was not found.
func (c *Client) GetDestination(name string) (Destination, error) {
	c.destinationsMu.RLock()
	defer c.destinationsMu.RUnlock()

	dst, ok := c.destinations[model.NewEndpoint(name)]
	if !ok {
		return nil, fmt.Errorf("destination %s: not found", name)
	}
	return dst, nil
}

// Destination starts a new destination with a given configuration.
// This call blocks until it is successfully announced to the control server.
// The destination can be closed either via cancelling the context or calling its close func.
func (c *Client) Destination(ctx context.Context, cfg DestinationConfig) (Destination, error) {
	c.destinationsMu.Lock()
	defer c.destinationsMu.Unlock()

	if _, ok := c.destinations[cfg.Endpoint]; ok {
		return nil, fmt.Errorf("destination %s already exists, remove old one first", cfg.Endpoint)
	}

	clDst, err := newClientDestination(ctx, c, cfg)
	if err != nil {
		return nil, err
	}

	c.destinations[cfg.Endpoint] = clDst
	c.logger.Info("added destination", "endpoint", cfg.Endpoint)
	return clDst, nil
}

func (c *Client) removeDestination(endpoint model.Endpoint) {
	c.destinationsMu.Lock()
	defer c.destinationsMu.Unlock()

	delete(c.destinations, endpoint)
	c.logger.Info("removed destination", "endpoint", endpoint)
}

// Sources returns the set of currently active sources
func (c *Client) Sources() []string {
	c.sourcesMu.RLock()
	defer c.sourcesMu.RUnlock()

	return model.EndpointNames(slices.Collect(maps.Keys(c.sources)))
}

// GetSource returns a source by its name. Returns an error if the source was not found.
func (c *Client) GetSource(name string) (Source, error) {
	c.sourcesMu.RLock()
	defer c.sourcesMu.RUnlock()

	src, ok := c.sources[model.NewEndpoint(name)]
	if !ok {
		return nil, fmt.Errorf("source %s: not found", name)
	}
	return src, nil
}

// Source starts a new source with a given configuration.
// This call blocks until it is successfully announced to the control server.
// The source can be closed either via cancelling the context or calling its close func.
func (c *Client) Source(ctx context.Context, cfg SourceConfig) (Source, error) {
	c.sourcesMu.Lock()
	defer c.sourcesMu.Unlock()

	if _, ok := c.sources[cfg.Endpoint]; ok {
		return nil, fmt.Errorf("source %s already exists, remove old one first", cfg.Endpoint)
	}

	clSrc, err := newClientSource(ctx, c, cfg)
	if err != nil {
		return nil, err
	}

	c.sources[cfg.Endpoint] = clSrc
	c.logger.Info("added source", "endpoint", cfg.Endpoint)
	return clSrc, nil
}

func (c *Client) removeSource(endpoint model.Endpoint) {
	c.sourcesMu.Lock()
	defer c.sourcesMu.Unlock()

	delete(c.sources, endpoint)
	c.logger.Info("removed source", "endpoint", endpoint)
}

// Close closes this client. It disconnects the client and all endpoints (destinations and sources) associated with it.
func (c *Client) Close() error {
	c.ctxCancel(net.ErrClosed)
	<-c.closer
	return nil
}

func (c *Client) closeEndpoints() {
	for _, dstName := range c.Destinations() {
		if dst, err := c.GetDestination(dstName); err == nil {
			if err := dst.Close(); err != nil {
				slogc.Fine(c.logger, "error closing destination", "dst", dstName, "err", err)
			}
		}
	}
	for _, srcName := range c.Sources() {
		if src, err := c.GetSource(srcName); err == nil {
			if err := src.Close(); err != nil {
				slogc.Fine(c.logger, "error closing source", "src", srcName, "err", err)
			}
		}
	}
}

func (c *Client) run(ctx context.Context, transport *quic.Transport, errCh chan error) error {
	sess, err := c.connect(ctx, transport, nil)
	if err != nil {
		errCh <- err
		return err
	}
	close(errCh)

	var boff reliable.SpinBackoff
	for {
		if err := c.runSession(ctx, sess); err != nil {
			c.logger.Error("session ended", "err", err)
			if errors.Is(err, context.Canceled) {
				return err
			}
		}

		if err := boff.Wait(ctx); err != nil {
			return err
		}

		if sess, err = c.reconnect(ctx, transport, sess.retoken); err != nil {
			return err
		}
	}
}

type session struct {
	conn    *quic.Conn
	addrs   *notify.V[client.AdvertiseAddrs]
	retoken []byte
}

func (c *Client) connect(ctx context.Context, transport *quic.Transport, retoken []byte) (*session, error) {
	c.logger.Debug("dialing target", "addr", c.controlAddr)
	conn, err := transport.Dial(ctx, c.controlAddr, &tls.Config{
		ServerName: c.controlHost,
		RootCAs:    c.controlCAs,
		NextProtos: model.ClientNextProtos,
	}, quicc.StdConfig)
	if err != nil {
		return nil, fmt.Errorf("dial server %s: %w", c.controlAddr, err)
	}

	c.logger.Debug("authenticating", "addr", c.controlAddr)

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open authentication stream: %w", err)
	}
	defer func() {
		if err := authStream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing auth stream", "err", err)
		}
	}()

	if err := proto.Write(authStream, &pbclient.Authenticate{
		Token:          c.token,
		ReconnectToken: retoken,
		BuildVersion:   model.BuildVersion(),
	}); err != nil {
		return nil, fmt.Errorf("write authentication: %w", err)
	}

	resp := &pbclient.AuthenticateResp{}
	if err := proto.Read(authStream, resp); err != nil {
		return nil, fmt.Errorf("authentication read failed: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("authentication failed: %w", resp.Error)
	}

	addrs := client.AdvertiseAddrs{
		STUN:  []netip.AddrPort{resp.Public.AsNetip()},
		Local: c.natlocal.Get(),
		PMP:   c.natpmp.Get(),
	}

	c.logger.Info("authenticated to server", "addr", c.controlAddr, "direct", addrs)
	return &session{conn, notify.New(addrs), resp.ReconnectToken}, nil
}

func (c *Client) reconnect(ctx context.Context, transport *quic.Transport, retoken []byte) (*session, error) {
	d := reliable.MinBackoff
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		c.logger.Debug("backoff wait", "d", d)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}

		if sess, err := c.connect(ctx, transport, retoken); err != nil {
			c.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return sess, nil
		}

		d = reliable.NextBackoff(d)
		t.Reset(d)
	}
}

func (c *Client) runSession(ctx context.Context, sess *session) error {
	defer func() {
		if err := sess.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(c.logger, "error closing connection", "err", err)
		}
	}()

	go func() {
		err := c.natlocal.Listen(ctx, func(ap []netip.AddrPort) error {
			c.logger.Debug("updating nat local", "addrs", ap)
			sess.addrs.Update(func(d client.AdvertiseAddrs) client.AdvertiseAddrs {
				d.Local = ap
				return d
			})
			return nil
		})
		if err != nil {
			slogc.Fine(c.logger, "closing nat local listener", "err", err)
		}
	}()

	go func() {
		err := c.natpmp.Listen(ctx, func(ap []netip.AddrPort) error {
			c.logger.Debug("updating nat pmp", "addrs", ap)
			sess.addrs.Update(func(d client.AdvertiseAddrs) client.AdvertiseAddrs {
				d.PMP = ap
				return d
			})
			return nil
		})
		if err != nil {
			slogc.Fine(c.logger, "closing nat pmp listener", "err", err)
		}
	}()

	c.currentSession.Set(sess)
	defer c.currentSession.Set(nil)

	c.connStatus.Store(statusc.Connected)
	defer c.connStatus.Store(statusc.Reconnecting)

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-sess.conn.Context().Done():
		return context.Cause(sess.conn.Context())
	}
}

type ClientStatus struct {
	Status       statusc.Status                    `json:"status"`
	Destinations map[model.Endpoint]EndpointStatus `json:"destinations"`
	Sources      map[model.Endpoint]EndpointStatus `json:"sources"`
}

// Status returns the client and all added peers statuses
func (c *Client) Status(ctx context.Context) (ClientStatus, error) {
	stat := c.connStatus.Load().(statusc.Status)

	dsts, err := c.destinationsStatus(ctx)
	if err != nil {
		return ClientStatus{}, err
	}

	srcs, err := c.sourcesStatus(ctx)
	if err != nil {
		return ClientStatus{}, err
	}

	return ClientStatus{
		Status:       stat,
		Destinations: dsts,
		Sources:      srcs,
	}, nil
}

func (c *Client) destinationsStatus(ctx context.Context) (map[model.Endpoint]EndpointStatus, error) {
	var err error
	statuses := map[model.Endpoint]EndpointStatus{}

	c.destinationsMu.RLock()
	defer c.destinationsMu.RUnlock()

	for ep, dst := range c.destinations {
		statuses[ep], err = dst.Status(ctx)
		if err != nil {
			return nil, err
		}
	}

	return statuses, nil
}

func (c *Client) sourcesStatus(ctx context.Context) (map[model.Endpoint]EndpointStatus, error) {
	var err error
	statuses := map[model.Endpoint]EndpointStatus{}

	c.sourcesMu.RLock()
	defer c.sourcesMu.RUnlock()

	for ep, src := range c.sources {
		statuses[ep], err = src.Status(ctx)
		if err != nil {
			return nil, err
		}
	}

	return statuses, nil
}

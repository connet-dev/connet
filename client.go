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
)

var ErrClientClosed = errors.New("client closed")

type Client struct {
	config

	directServer *directServer

	destinations   map[model.Endpoint]*Destination
	destinationsMu sync.RWMutex
	sources        map[model.Endpoint]*Source
	sourcesMu      sync.RWMutex

	connStatus     atomic.Value
	currentSession *notify.V[*session]
	ctxCancel      context.CancelCauseFunc
	closer         chan struct{}

	addrs    *notify.V[advertiseAddrs]
	natlocal *nat.Local
	natpmp   *nat.PMP
}

type advertiseAddrs struct {
	STUN  []netip.AddrPort
	PMP   []netip.AddrPort
	Local []netip.AddrPort
}

func (d advertiseAddrs) all() []netip.AddrPort {
	addrs := make([]netip.AddrPort, 0, len(d.STUN)+len(d.PMP)+len(d.Local))
	addrs = append(addrs, d.STUN...)
	addrs = append(addrs, d.PMP...)
	addrs = append(addrs, d.Local...)
	return addrs
}

// Connect starts a new client and connects it to the control server.
// This call blocks until the server is connected or an error is detected.
// The client can be stopped either by canceling this context or via calling Close. Stopping the client will also
// stop all active endpoints (destinations/sources) associated with this client
func Connect(ctx context.Context, opts ...Option) (*Client, error) {
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}

	c := &Client{
		config: *cfg,

		destinations: map[model.Endpoint]*Destination{},
		sources:      map[model.Endpoint]*Source{},

		currentSession: notify.New[*session](nil),
		closer:         make(chan struct{}),

		addrs: notify.NewEmpty[advertiseAddrs](),
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

	ds, err := newDirectServer(transport, c.handshakeIdleTimeout, c.logger)
	if err != nil {
		errCh <- fmt.Errorf("create direct server: %w", err)
		return
	}
	c.directServer = ds

	c.natlocal = nat.NewLocal(uint16(c.directAddr.Port), c.logger)
	c.natpmp = nat.NewPMP(c.natPMP, transport, uint16(c.directAddr.Port), c.logger)

	g := reliable.NewGroup(ctx)

	g.Go(ds.Run)
	g.Go(c.natpmp.Run)
	g.Go(c.listenNatlocal)
	g.Go(c.listenNatpmp)
	g.Go(func(ctx context.Context) error { return c.run(ctx, transport, errCh) })

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
func (c *Client) GetDestination(name string) (*Destination, error) {
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
// The destination can be closed either via canceling the context or calling its close func.
func (c *Client) Destination(ctx context.Context, cfg DestinationConfig) (*Destination, error) {
	c.destinationsMu.Lock()
	defer c.destinationsMu.Unlock()

	if _, ok := c.destinations[cfg.Endpoint]; ok {
		return nil, fmt.Errorf("destination %s already exists, remove old one first", cfg.Endpoint)
	}

	clDst, err := newDestination(ctx, c, cfg)
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
func (c *Client) GetSource(name string) (*Source, error) {
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
// The source can be closed either via canceling the context or calling its close func.
func (c *Client) Source(ctx context.Context, cfg SourceConfig) (*Source, error) {
	c.sourcesMu.Lock()
	defer c.sourcesMu.Unlock()

	if _, ok := c.sources[cfg.Endpoint]; ok {
		return nil, fmt.Errorf("source %s already exists, remove old one first", cfg.Endpoint)
	}

	clSrc, err := newSource(ctx, c, cfg)
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
	c.ctxCancel(ErrClientClosed)
	<-c.closer
	return nil
}

func (c *Client) closeEndpoints() {
	for _, dstName := range c.Destinations() {
		if dst, err := c.GetDestination(dstName); err == nil {
			if err := dst.Close(); err != nil {
				slogc.Fine(c.logger, "error closing destination", "endpoint", dstName, "err", err)
			}
		}
	}
	for _, srcName := range c.Sources() {
		if src, err := c.GetSource(srcName); err == nil {
			if err := src.Close(); err != nil {
				slogc.Fine(c.logger, "error closing source", "endpoint", srcName, "err", err)
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
	retoken []byte
}

func (c *Client) connect(ctx context.Context, transport *quic.Transport, retoken []byte) (*session, error) {
	c.logger.Debug("dialing target", "addr", c.controlAddr, "name", c.controlHost)
	conn, err := transport.Dial(ctx, c.controlAddr, &tls.Config{
		ServerName: c.controlHost,
		RootCAs:    c.controlCAs,
		NextProtos: model.ClientNextProtos,
	}, quicc.ClientConfig(c.handshakeIdleTimeout))
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

	if err := proto.Write(authStream, &pbclient.AuthenticateReq{
		Token:          c.token,
		ReconnectToken: retoken,
		BuildVersion:   model.BuildVersion(),
		Metadata:       c.metadata,
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

	c.addrs.Update(func(t advertiseAddrs) advertiseAddrs {
		c.logger.Debug("updating nat stun", "addr", resp.Public.AsNetip())
		t.STUN = []netip.AddrPort{resp.Public.AsNetip()}
		return t
	})

	c.logger.Info("authenticated to server", "addr", c.controlAddr, "direct", resp.Public.AsNetip())
	return &session{conn, resp.ReconnectToken}, nil
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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

func (c *Client) listenNatlocal(ctx context.Context) error {
	return c.natlocal.Listen(ctx, func(ap []netip.AddrPort) error {
		c.logger.Debug("updating nat local", "addrs", ap)
		c.addrs.Update(func(d advertiseAddrs) advertiseAddrs {
			d.Local = ap
			return d
		})
		return nil
	})
}

func (c *Client) listenNatpmp(ctx context.Context) error {
	return c.natpmp.Listen(ctx, func(ap []netip.AddrPort) error {
		c.logger.Debug("updating nat pmp", "addrs", ap)
		c.addrs.Update(func(d advertiseAddrs) advertiseAddrs {
			d.PMP = ap
			return d
		})
		return nil
	})
}

type ClientStatus struct {
	// Overall status of this client
	Status statusc.Status `json:"status"`
	// Status of each active destination for this client
	Destinations map[model.Endpoint]DestinationStatus `json:"destinations"`
	// Status of each active source for this client
	Sources map[model.Endpoint]SourceStatus `json:"sources"`
}

// Status returns status of the client and all active endpoints
func (c *Client) Status(ctx context.Context) (ClientStatus, error) {
	stat := c.connStatus.Load().(statusc.Status)

	dsts, err := c.destinationsStatus()
	if err != nil {
		return ClientStatus{}, err
	}

	srcs, err := c.sourcesStatus()
	if err != nil {
		return ClientStatus{}, err
	}

	return ClientStatus{
		Status:       stat,
		Destinations: dsts,
		Sources:      srcs,
	}, nil
}

func (c *Client) destinationsStatus() (map[model.Endpoint]DestinationStatus, error) {
	var err error
	statuses := map[model.Endpoint]DestinationStatus{}

	c.destinationsMu.RLock()
	defer c.destinationsMu.RUnlock()

	for ep, dst := range c.destinations {
		statuses[ep], err = dst.Status()
		if err != nil {
			return nil, err
		}
	}

	return statuses, nil
}

func (c *Client) sourcesStatus() (map[model.Endpoint]SourceStatus, error) {
	var err error
	statuses := map[model.Endpoint]SourceStatus{}

	c.sourcesMu.RLock()
	defer c.sourcesMu.RUnlock()

	for ep, src := range c.sources {
		statuses[ep], err = src.Status()
		if err != nil {
			return nil, err
		}
	}

	return statuses, nil
}

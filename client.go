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
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/notify"
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

	dsts   map[model.Forward]*clientDestination
	dstsMu sync.RWMutex
	srcs   map[model.Forward]*clientSource
	srcsMu sync.RWMutex

	cancel     context.CancelCauseFunc
	connStatus atomic.Value
	sess       *notify.V[*session]
	closer     chan struct{}
}

// Connect starts a new client and connects it to the control server
// the client can be stopped either by canceling this context (TODO should it be separate option) or via calling Close
// Either will close all active source/destinations associated with this client
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

		dsts: map[model.Forward]*clientDestination{},
		srcs: map[model.Forward]*clientSource{},

		sess:   notify.New[*session](nil),
		closer: make(chan struct{}),
	}
	c.connStatus.Store(statusc.NotConnected)

	ctx, cancel := context.WithCancelCause(ctx)
	c.cancel = cancel

	errCh := make(chan error)
	go c.runClient(ctx, errCh)

	if err := <-errCh; err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) runClient(ctx context.Context, errCh chan error) {
	c.logger.Debug("start udp listener")
	udpConn, err := net.ListenUDP("udp", c.directAddr)
	if err != nil {
		errCh <- fmt.Errorf("listen direct address: %w", err)
		return
	}
	defer udpConn.Close()

	c.logger.Debug("start quic listener")
	transport := quicc.ClientTransport(udpConn, c.directResetKey)
	defer transport.Close()

	ds, err := client.NewDirectServer(transport, c.logger)
	if err != nil {
		errCh <- fmt.Errorf("create direct server: %w", err)
		return
	}
	c.directServer = ds

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return ds.Run(ctx) })
	g.Go(func() error { return c.run(ctx, transport, errCh) })

	if err := g.Wait(); err != nil {
		// TODO
		close(c.closer)
	}
}

func (c *Client) Destinations() []string {
	c.dstsMu.RLock()
	defer c.dstsMu.RUnlock()

	return model.ForwardNames(slices.Collect(maps.Keys(c.dsts)))
}

func (c *Client) GetDestination(name string) (Destination, error) {
	c.dstsMu.RLock()
	defer c.dstsMu.RUnlock()

	dst, ok := c.dsts[model.NewForward(name)]
	if !ok {
		return nil, fmt.Errorf("destination %s: not found", name)
	}
	return dst, nil
}

// Destination starts a new destination with a given configuration
// Blocks until it is succesfully announced to the control server
// The destination can be closed either via cancelling the context or calling its close func
func (c *Client) Destination(ctx context.Context, cfg client.DestinationConfig) (Destination, error) {
	clDst, err := newClientDestination(ctx, c, cfg)
	if err != nil {
		return nil, err
	}

	c.dstsMu.Lock()
	defer c.dstsMu.Unlock()

	c.dsts[cfg.Forward] = clDst
	return clDst, nil
}

func (c *Client) Sources() []string {
	c.srcsMu.RLock()
	defer c.srcsMu.RUnlock()

	return model.ForwardNames(slices.Collect(maps.Keys(c.srcs)))
}

func (c *Client) GetSource(name string) (Source, error) {
	c.srcsMu.RLock()
	defer c.srcsMu.RUnlock()

	src, ok := c.srcs[model.NewForward(name)]
	if !ok {
		return nil, fmt.Errorf("source %s: not found", name)
	}
	return src, nil
}

// Source starts a new source with a given configuration
// Blocks until it is succesfully announced to the control server
// The source can be closed either via cancelling the context or calling its close func
func (c *Client) Source(ctx context.Context, cfg client.SourceConfig) (Source, error) {
	clSrc, err := newClientSource(ctx, c, cfg)
	if err != nil {
		return nil, err
	}

	c.srcsMu.Lock()
	defer c.srcsMu.Unlock()

	c.srcs[cfg.Forward] = clSrc
	return clSrc, nil
}

func (c *Client) Close() error {
	c.cancel(net.ErrClosed)
	<-c.closer
	return nil
}

func (c *Client) run(ctx context.Context, transport *quic.Transport, errCh chan error) error {
	sess, err := c.connect(ctx, transport, nil)
	if err != nil {
		errCh <- err
		return err
	}
	close(errCh)

	for {
		if err := c.runSession(ctx, sess); err != nil {
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

		if sess, err = c.reconnect(ctx, transport, sess.retoken); err != nil {
			return err
		}
	}
}

type session struct {
	conn    quic.Connection
	addrs   []netip.AddrPort
	retoken []byte
}

func (c *Client) connect(ctx context.Context, transport *quic.Transport, retoken []byte) (*session, error) {
	c.logger.Debug("dialing target", "addr", c.controlAddr)
	// TODO dial timeout if server is not accessible?
	conn, err := transport.Dial(quicc.RTTContext(ctx), c.controlAddr, &tls.Config{
		ServerName: c.controlHost,
		RootCAs:    c.controlCAs,
		NextProtos: []string{"connet"},
	}, quicc.StdConfig)
	if err != nil {
		return nil, fmt.Errorf("dial server %s: %w", c.controlAddr, err)
	}

	c.logger.Debug("authenticating", "addr", c.controlAddr)

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open authentication stream: %w", err)
	}
	defer authStream.Close()

	if err := pb.Write(authStream, &pbs.Authenticate{
		Token:          c.token,
		ReconnectToken: retoken,
	}); err != nil {
		return nil, fmt.Errorf("write authentication: %w", err)
	}

	resp := &pbs.AuthenticateResp{}
	if err := pb.Read(authStream, resp); err != nil {
		return nil, fmt.Errorf("authentication read failed: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("authentication failed: %w", resp.Error)
	}

	localAddrs, err := netc.LocalAddrs()
	if err != nil {
		return nil, fmt.Errorf("local addrs: %w", err)
	}
	localAddrPorts := make([]netip.AddrPort, len(localAddrs))
	for i, addr := range localAddrs {
		localAddrPorts[i] = netip.AddrPortFrom(addr, c.clientConfig.directAddr.AddrPort().Port())
	}

	directAddrs := append(localAddrPorts, resp.Public.AsNetip())

	c.logger.Info("authenticated to server", "addr", c.controlAddr, "direct", directAddrs)
	return &session{conn, directAddrs, resp.ReconnectToken}, nil
}

func (c *Client) reconnect(ctx context.Context, transport *quic.Transport, retoken []byte) (*session, error) {
	d := netc.MinBackoff
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

		d = netc.NextBackoff(d)
		t.Reset(d)
	}
}

func (c *Client) runSession(ctx context.Context, sess *session) error {
	defer sess.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_Unknown), "connection closed")

	c.sess.Set(sess)
	defer c.sess.Set(nil)

	c.connStatus.Store(statusc.Connected)
	defer c.connStatus.Store(statusc.Disconnected)

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-sess.conn.Context().Done():
		return context.Cause(sess.conn.Context())
	}
}

type ClientStatus struct {
	Status       statusc.Status                      `json:"status"`
	Destinations map[model.Forward]client.PeerStatus `json:"destinations"`
	Sources      map[model.Forward]client.PeerStatus `json:"sources"`
}

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

func (c *Client) destinationsStatus() (map[model.Forward]client.PeerStatus, error) {
	var err error
	statuses := map[model.Forward]client.PeerStatus{}

	c.dstsMu.RLock()
	defer c.dstsMu.RUnlock()

	for fwd, dst := range c.dsts {
		statuses[fwd], err = dst.Status()
		if err != nil {
			return nil, err
		}
	}

	return statuses, nil
}

func (c *Client) sourcesStatus() (map[model.Forward]client.PeerStatus, error) {
	var err error
	statuses := map[model.Forward]client.PeerStatus{}

	c.srcsMu.RLock()
	defer c.srcsMu.RUnlock()

	for fwd, src := range c.srcs {
		statuses[fwd], err = src.Status()
		if err != nil {
			return nil, err
		}
	}

	return statuses, nil
}

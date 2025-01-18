package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	"github.com/connet-dev/connet/quicc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type clientAuth struct {
	fwd         model.Forward
	destination bool
	source      bool
}

type tlsAuthenticator func(chi *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error)
type clientAuthenticator func(serverName string, certs []*x509.Certificate) *clientAuth

func newClientsServer(cfg Config, tlsAuth tlsAuthenticator, clAuth clientAuthenticator) *clientsServer {
	tlsConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"connet-relay"},
	}
	tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		return tlsAuth(chi, tlsConf)
	}

	return &clientsServer{
		tlsConf: tlsConf,
		auth:    clAuth,

		forwards: map[model.Forward]*forwardClients{},

		logger: cfg.Logger.With("relay-clients", cfg.Hostport),
	}
}

type clientsServer struct {
	tlsConf *tls.Config
	auth    clientAuthenticator

	forwards  map[model.Forward]*forwardClients
	forwardMu sync.RWMutex

	logger *slog.Logger
}

type forwardClients struct {
	fwd          model.Forward
	destinations map[certc.Key]*clientConn
	sources      map[certc.Key]*clientConn
	mu           sync.RWMutex
}

func (d *forwardClients) get() []*clientConn {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return slices.Collect(maps.Values(d.destinations))
}

func (d *forwardClients) removeDestination(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.destinations, conn.key)

	return d.empty()
}

func (d *forwardClients) removeSource(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.sources, conn.key)

	return d.empty()
}

func (d *forwardClients) empty() bool {
	return (len(d.destinations) + len(d.sources)) == 0
}

func (s *clientsServer) getByForward(fwd model.Forward) *forwardClients {
	s.forwardMu.RLock()
	dst := s.forwards[fwd]
	s.forwardMu.RUnlock()
	if dst != nil {
		return dst
	}

	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()

	dst = s.forwards[fwd]
	if dst != nil {
		return dst
	}

	dst = &forwardClients{
		fwd:          fwd,
		destinations: map[certc.Key]*clientConn{},
		sources:      map[certc.Key]*clientConn{},
	}
	s.forwards[fwd] = dst
	return dst
}

func (s *clientsServer) removeByClients(fcs *forwardClients) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()

	fcs.mu.Lock()
	defer fcs.mu.Unlock()

	if fcs.empty() {
		delete(s.forwards, fcs.fwd)
	}
}

func (s *clientsServer) addDestination(conn *clientConn) *forwardClients {
	dst := s.getByForward(conn.fwd)

	dst.mu.Lock()
	defer dst.mu.Unlock()

	dst.destinations[conn.key] = conn

	return dst
}

func (s *clientsServer) removeDestination(fcs *forwardClients, conn *clientConn) {
	if fcs.removeDestination(conn) {
		s.removeByClients(fcs)
	}
}

func (s *clientsServer) addSource(conn *clientConn) *forwardClients {
	target := s.getByForward(conn.fwd)

	target.mu.Lock()
	defer target.mu.Unlock()

	target.sources[conn.key] = conn

	return target
}

func (s *clientsServer) removeSource(fcs *forwardClients, conn *clientConn) {
	if fcs.removeSource(conn) {
		s.removeByClients(fcs)
	}
}

func (s *clientsServer) run(ctx context.Context, transport *quic.Transport) error {
	l, err := transport.Listen(s.tlsConf, &quic.Config{
		MaxIdleTimeout:  20 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		Tracer:          quicc.RTTTracer,
	})
	if err != nil {
		return kleverr.Ret(err)
	}
	defer l.Close()

	s.logger.Info("accepting client connections", "addr", transport.Conn.LocalAddr())
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			s.logger.Debug("accept error", "err", err)
			return kleverr.Ret(err)
		}
		s.logger.Info("new client connected", "remote", conn.RemoteAddr())

		rc := &clientConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go rc.run(ctx)
	}
}

type clientConn struct {
	server *clientsServer
	conn   quic.Connection
	logger *slog.Logger

	fwd model.Forward
	key certc.Key
}

func (c *clientConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_Unknown), "connection closed")

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running", "err", err)
	}
}

func (c *clientConn) runErr(ctx context.Context) error {
	serverName := c.conn.ConnectionState().TLS.ServerName
	certs := c.conn.ConnectionState().TLS.PeerCertificates
	auth := c.server.auth(serverName, certs)
	if auth == nil {
		return c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "authentication missing")
	}

	switch {
	case auth.destination:
		c.fwd = auth.fwd
		c.key = certc.NewKey(certs[0])

		fcs := c.server.addDestination(c)
		defer c.server.removeDestination(fcs, c)

		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			go c.runDestinationStream(ctx, stream)
		}
	case auth.source:
		c.fwd = auth.fwd
		c.key = certc.NewKey(certs[0])

		fcs := c.server.addSource(c)
		defer c.server.removeSource(fcs, c)

		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			go c.runSourceStream(ctx, stream, fcs)
		}
	default:
		return kleverr.Newf("not a destination or a source")
	}
}

func (c *clientConn) runDestinationStream(ctx context.Context, stream quic.Stream) {
	defer stream.Close()

	if err := c.runDestinationStreamErr(ctx, stream); err != nil {
		c.logger.Debug("error while running destination", "err", err)
	}
}

func (c *clientConn) runDestinationStreamErr(ctx context.Context, stream quic.Stream) error {
	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Heartbeat != nil:
		return c.heartbeat(ctx, stream, req.Heartbeat)
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *clientConn) runSourceStream(ctx context.Context, stream quic.Stream, fcs *forwardClients) {
	defer stream.Close()

	if err := c.runSourceStreamErr(ctx, stream, fcs); err != nil {
		c.logger.Debug("error while running destination", "err", err)
	}
}

func (c *clientConn) runSourceStreamErr(ctx context.Context, stream quic.Stream, fcs *forwardClients) error {
	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Connect != nil:
		return c.connect(ctx, stream, fcs)
	case req.Heartbeat != nil:
		return c.heartbeat(ctx, stream, req.Heartbeat)
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *clientConn) connect(ctx context.Context, stream quic.Stream, fcs *forwardClients) error {
	dests := fcs.get()
	for _, dest := range dests {
		if err := c.connectDestination(ctx, stream, dest); err != nil {
			c.logger.Debug("could not dial destination", "err", err)
		} else {
			// connect was success
			return nil
		}
	}

	err := pb.NewError(pb.Error_DestinationNotFound, "could not dial destinations: %d", len(dests))
	return pb.Write(stream, &pbc.Response{Error: err})
}

func (c *clientConn) connectDestination(ctx context.Context, srcStream quic.Stream, dest *clientConn) error {
	dstStream, err := dest.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Newf("could not open stream: %w", err)
	}

	if err := pb.Write(dstStream, &pbc.Request{
		Connect: &pbc.Request_Connect{},
	}); err != nil {
		return kleverr.Newf("could not write request: %w", err)
	}

	if _, err := pbc.ReadResponse(dstStream); err != nil {
		return kleverr.Newf("could not read response: %w", err)
	}

	if err := pb.Write(srcStream, &pbc.Response{}); err != nil {
		return kleverr.Newf("could not write response: %w", err)
	}

	c.logger.Debug("joining conns", "forward", c.fwd)
	err = netc.Join(ctx, srcStream, dstStream)
	c.logger.Debug("disconnected conns", "forward", c.fwd, "err", err)
	return nil
}

func (c *clientConn) heartbeat(ctx context.Context, stream quic.Stream, hbt *pbc.Heartbeat) error {
	if err := pb.Write(stream, &pbc.Response{Heartbeat: hbt}); err != nil {
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
			req, err := pbc.ReadRequest(stream)
			if err != nil {
				return err
			}
			if req.Heartbeat == nil {
				respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
				if err := pb.Write(stream, &pbc.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			if err := pb.Write(stream, &pbc.Response{Heartbeat: req.Heartbeat}); err != nil {
				return err
			}
			if rttStats := quicc.RTTStats(c.conn); rttStats != nil {
				c.logger.Debug("rtt", "last", rttStats.LatestRTT(), "smoothed", rttStats.SmoothedRTT())
			}
		}
	})

	return g.Wait()
}

func (c *clientConn) unknown(_ context.Context, stream quic.Stream, req *pbc.Request) error {
	c.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(stream, &pbc.Response{Error: err})
}

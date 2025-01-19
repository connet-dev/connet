package relay

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"math"
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
	fwd  model.Forward
	role model.Role
	key  certc.Key
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

func (d *forwardClients) getDestinations() []*clientConn {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return slices.SortedFunc(maps.Values(d.destinations), func(l, r *clientConn) int {
		var ld, rd = time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)

		if rtt := quicc.RTTStats(l.conn); rtt != nil {
			ld = rtt.SmoothedRTT()
		}
		if rtt := quicc.RTTStats(r.conn); rtt != nil {
			rd = rtt.SmoothedRTT()
		}

		return cmp.Compare(ld, rd)
	})
}

func (d *forwardClients) removeDestination(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.destinations, conn.auth.key)

	return d.empty()
}

func (d *forwardClients) removeSource(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.sources, conn.auth.key)

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
	dst := s.getByForward(conn.auth.fwd)

	dst.mu.Lock()
	defer dst.mu.Unlock()

	dst.destinations[conn.auth.key] = conn

	return dst
}

func (s *clientsServer) removeDestination(fcs *forwardClients, conn *clientConn) {
	if fcs.removeDestination(conn) {
		s.removeByClients(fcs)
	}
}

func (s *clientsServer) addSource(conn *clientConn) *forwardClients {
	target := s.getByForward(conn.auth.fwd)

	target.mu.Lock()
	defer target.mu.Unlock()

	target.sources[conn.auth.key] = conn

	return target
}

func (s *clientsServer) removeSource(fcs *forwardClients, conn *clientConn) {
	if fcs.removeSource(conn) {
		s.removeByClients(fcs)
	}
}

func (s *clientsServer) run(ctx context.Context, transport *quic.Transport) error {
	l, err := transport.Listen(s.tlsConf, quicc.StdConfig)
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

	auth *clientAuth
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
	if auth := c.server.auth(serverName, certs); auth == nil {
		return c.conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_AuthenticationFailed), "authentication missing")
	} else {
		c.auth = auth
		c.logger = c.logger.With("fwd", auth.fwd, "key", auth.key)
	}

	if err := c.check(ctx); err != nil {
		return err
	}

	switch c.auth.role {
	case model.Destination:
		return c.runDestination(ctx)
	case model.Source:
		return c.runSource(ctx)
	default:
		return kleverr.Newf("not a destination or a source")
	}
}

func (c *clientConn) check(ctx context.Context) error {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	if _, err := pbc.ReadRequest(stream); err != nil {
		return err
	} else if err := pb.Write(stream, &pbc.Response{}); err != nil {
		return err
	}

	return nil
}

func (c *clientConn) runDestination(ctx context.Context) error {
	fcs := c.server.addDestination(c)
	defer c.server.removeDestination(fcs, c)

	quicc.RTTLogStats(c.conn, c.logger)
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-c.conn.Context().Done():
			return context.Cause(c.conn.Context())
		case <-time.After(30 * time.Second):
			quicc.RTTLogStats(c.conn, c.logger)
		}
	}
}

func (c *clientConn) runSource(ctx context.Context) error {
	fcs := c.server.addSource(c)
	defer c.server.removeSource(fcs, c)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		quicc.RTTLogStats(c.conn, c.logger)
		for {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-c.conn.Context().Done():
				return context.Cause(c.conn.Context())
			case <-time.After(30 * time.Second):
				quicc.RTTLogStats(c.conn, c.logger)
			}
		}
	})

	g.Go(func() error {
		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			go c.runSourceStream(ctx, stream, fcs)
		}
	})

	return g.Wait()
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
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *clientConn) connect(ctx context.Context, stream quic.Stream, fcs *forwardClients) error {
	dests := fcs.getDestinations()
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

	c.logger.Debug("joining conns")
	err = netc.Join(ctx, srcStream, dstStream)
	c.logger.Debug("disconnected conns", "err", err)
	return nil
}

func (c *clientConn) unknown(_ context.Context, stream quic.Stream, req *pbc.Request) error {
	c.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(stream, &pbc.Response{Error: err})
}

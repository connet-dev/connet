package relay

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type clientAuth struct {
	endpoint model.Endpoint
	role     model.Role
	key      model.Key
}

type tlsAuthenticator func(chi *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error)
type clientAuthenticator func(serverName string, certs []*x509.Certificate) *clientAuth

func newClientsServer(cfg Config, tlsAuth tlsAuthenticator, clAuth clientAuthenticator) *clientsServer {
	tlsConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: model.ConnectRelayNextProtos,
	}
	tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		return tlsAuth(chi, tlsConf)
	}

	return &clientsServer{
		tlsConf: tlsConf,
		auth:    clAuth,

		endpoints: map[model.Endpoint]*endpointClients{},

		logger: cfg.Logger.With("server", "relay-clients"),
	}
}

type clientsServer struct {
	tlsConf *tls.Config
	auth    clientAuthenticator

	endpoints   map[model.Endpoint]*endpointClients
	endpointsMu sync.RWMutex

	logger *slog.Logger
}

type endpointClients struct {
	endpoint     model.Endpoint
	destinations map[model.Key]*clientConn
	sources      map[model.Key]*clientConn
	mu           sync.RWMutex
}

func (d *endpointClients) getDestinations() []*clientConn {
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

func (d *endpointClients) removeDestination(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.destinations, conn.auth.key)

	return d.empty()
}

func (d *endpointClients) removeSource(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.sources, conn.auth.key)

	return d.empty()
}

func (d *endpointClients) empty() bool {
	return (len(d.destinations) + len(d.sources)) == 0
}

func (s *clientsServer) getByEndpoint(endpoint model.Endpoint) *endpointClients {
	s.endpointsMu.RLock()
	dst := s.endpoints[endpoint]
	s.endpointsMu.RUnlock()
	if dst != nil {
		return dst
	}

	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()

	dst = s.endpoints[endpoint]
	if dst != nil {
		return dst
	}

	dst = &endpointClients{
		endpoint:     endpoint,
		destinations: map[model.Key]*clientConn{},
		sources:      map[model.Key]*clientConn{},
	}
	s.endpoints[endpoint] = dst
	return dst
}

func (s *clientsServer) removeByClients(fcs *endpointClients) {
	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()

	fcs.mu.Lock()
	defer fcs.mu.Unlock()

	if fcs.empty() {
		delete(s.endpoints, fcs.endpoint)
	}
}

func (s *clientsServer) addDestination(conn *clientConn) *endpointClients {
	dst := s.getByEndpoint(conn.auth.endpoint)

	dst.mu.Lock()
	defer dst.mu.Unlock()

	dst.destinations[conn.auth.key] = conn

	return dst
}

func (s *clientsServer) removeDestination(fcs *endpointClients, conn *clientConn) {
	if fcs.removeDestination(conn) {
		s.removeByClients(fcs)
	}
}

func (s *clientsServer) addSource(conn *clientConn) *endpointClients {
	target := s.getByEndpoint(conn.auth.endpoint)

	target.mu.Lock()
	defer target.mu.Unlock()

	target.sources[conn.auth.key] = conn

	return target
}

func (s *clientsServer) removeSource(fcs *endpointClients, conn *clientConn) {
	if fcs.removeSource(conn) {
		s.removeByClients(fcs)
	}
}

type clientsServerCfg struct {
	ingress           Ingress
	statelessResetKey *quic.StatelessResetKey
	addedTransport    func(*quic.Transport)
	removeTransport   func(*quic.Transport)
}

func (s *clientsServer) run(ctx context.Context, cfg clientsServerCfg) error {
	s.logger.Debug("start udp listener", "addr", cfg.ingress.Addr)
	udpConn, err := net.ListenUDP("udp", cfg.ingress.Addr)
	if err != nil {
		return fmt.Errorf("relay server listen: %w", err)
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			s.logger.Debug("error closing udp listener", "err", err)
		}
	}()

	s.logger.Debug("start quic listener", "addr", cfg.ingress.Addr)
	transport := quicc.ServerTransport(udpConn, cfg.statelessResetKey)
	defer func() {
		if err := transport.Close(); err != nil {
			s.logger.Debug("error closing transport", "err", err)
		}
	}()

	cfg.addedTransport(transport)
	defer cfg.removeTransport(transport)

	quicConf := quicc.StdConfig
	if cfg.ingress.Restr.IsNotEmpty() {
		quicConf = quicConf.Clone()
		quicConf.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
			if cfg.ingress.Restr.IsAllowedAddr(info.RemoteAddr) {
				return quicConf, nil
			}
			return nil, fmt.Errorf("client not allowed from %s", info.RemoteAddr.String())
		}
	}

	l, err := transport.Listen(s.tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("client server udp listen: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			s.logger.Debug("error closing clients listener", "err", err)
		}
	}()

	s.logger.Info("accepting client connections", "addr", transport.Conn.LocalAddr())
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			s.logger.Debug("accept error", "err", err)
			return fmt.Errorf("client server quic accept: %w", err)
		}

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
	conn   *quic.Conn
	logger *slog.Logger

	auth *clientAuth
}

func (c *clientConn) run(ctx context.Context) {
	c.logger.Info("new client connected", "proto", c.conn.ConnectionState().TLS.NegotiatedProtocol, "remote", c.conn.RemoteAddr())
	defer func() {
		if err := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			c.logger.Debug("error closing connection", "err", err)
		}
	}()

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running client conn", "err", err)
	}
}

var errNotRecognizedClient = errors.New("client not recognized as a destination or a source")

func (c *clientConn) runErr(ctx context.Context) error {
	serverName := c.conn.ConnectionState().TLS.ServerName
	certs := c.conn.ConnectionState().TLS.PeerCertificates
	if auth := c.server.auth(serverName, certs); auth == nil {
		return c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "authentication missing")
	} else {
		c.auth = auth
		c.logger = c.logger.With("endpoint", auth.endpoint, "role", auth.role, "key", auth.key)
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
		return errNotRecognizedClient
	}
}

func (c *clientConn) check(ctx context.Context) error {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept client stream: %w", err)
	}
	defer stream.Close()

	if _, err := pbconnect.ReadRequest(stream); err != nil {
		return fmt.Errorf("read client stream: %w", err)
	} else if err := proto.Write(stream, &pbconnect.Response{}); err != nil {
		return fmt.Errorf("write client stream: %w", err)
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
				return fmt.Errorf("accept source stream: %w", err)
			}
			go c.runSourceStream(ctx, stream, fcs)
		}
	})

	return g.Wait()
}

func (c *clientConn) runSourceStream(ctx context.Context, stream *quic.Stream, fcs *endpointClients) {
	defer stream.Close()

	if err := c.runSourceStreamErr(ctx, stream, fcs); err != nil {
		c.logger.Debug("error while running source", "err", err)
	}
}

func (c *clientConn) runSourceStreamErr(ctx context.Context, stream *quic.Stream, fcs *endpointClients) error {
	req, err := pbconnect.ReadRequest(stream)
	if err != nil {
		return fmt.Errorf("source stream read: %w", err)
	}

	switch {
	case req.Connect != nil:
		return c.connect(ctx, stream, fcs, req)
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *clientConn) connect(ctx context.Context, stream *quic.Stream, fcs *endpointClients, req *pbconnect.Request) error {
	dests := fcs.getDestinations()
	if len(dests) == 0 {
		err := pberror.NewError(pberror.Code_DestinationNotFound, "could not find destination")
		return proto.Write(stream, &pbconnect.Response{Error: err})
	}

	var pberrs []string
	for _, dest := range dests {
		if err := c.connectDestination(ctx, stream, dest, req); err != nil {
			if pberr := pberror.GetError(err); pberr != nil {
				pberrs = append(pberrs, pberr.Error())
			}
			c.logger.Debug("could not dial destination", "err", err)
		} else {
			// connect was success
			return nil
		}
	}

	err := pberror.NewError(pberror.Code_DestinationDialFailed, "could not dial destinations: %v", pberrs)
	return proto.Write(stream, &pbconnect.Response{Error: err})
}

func (c *clientConn) connectDestination(ctx context.Context, srcStream *quic.Stream, dest *clientConn, req *pbconnect.Request) error {
	dstStream, err := dest.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("destination open stream: %w", err)
	}

	if err := proto.Write(dstStream, req); err != nil {
		return fmt.Errorf("destination write request: %w", err)
	}

	resp, err := pbconnect.ReadResponse(dstStream)
	if err != nil {
		return fmt.Errorf("destination read response: %w", err)
	}

	if err := proto.Write(srcStream, resp); err != nil {
		return fmt.Errorf("source write response: %w", err)
	}

	c.logger.Debug("joining conns")
	err = netc.Join(srcStream, dstStream)
	c.logger.Debug("disconnected conns", "err", err)
	return nil
}

func (c *clientConn) unknown(_ context.Context, stream *quic.Stream, req *pbconnect.Request) error {
	c.logger.Error("unknown request", "req", req)
	err := pberror.NewError(pberror.Code_RequestUnknown, "unknown request: %v", req)
	return proto.Write(stream, &pbconnect.Response{Error: err})
}

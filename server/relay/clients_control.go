package relay

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/quic-go/quic-go"
)

type clientAuth struct {
	endpoint model.Endpoint
	role     model.Role
	key      model.Key
}

type clientAuthenticator func(serverName string, certs []*x509.Certificate) *clientAuth

type clientsControlServer struct {
	auth clientAuthenticator

	endpoints   map[model.Endpoint]*endpointServer
	endpointsMu sync.RWMutex

	logger *slog.Logger
}

type endpointServer struct {
	endpoint     model.Endpoint
	destinations map[model.Key]*clientConn
	sources      map[model.Key]*clientConn
	mu           sync.RWMutex
}

func (d *endpointServer) getDestinations() []*clientConn {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return slices.SortedFunc(maps.Values(d.destinations), func(l, r *clientConn) int {
		ld := l.conn.ConnectionStats().SmoothedRTT
		rd := r.conn.ConnectionStats().SmoothedRTT

		return cmp.Compare(ld, rd)
	})
}

func (d *endpointServer) removeDestination(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.destinations, conn.auth.key)

	return d.empty()
}

func (d *endpointServer) removeSource(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.sources, conn.auth.key)

	return d.empty()
}

func (d *endpointServer) empty() bool {
	return (len(d.destinations) + len(d.sources)) == 0
}

func (s *clientsControlServer) getByEndpoint(endpoint model.Endpoint) *endpointServer {
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

	dst = &endpointServer{
		endpoint:     endpoint,
		destinations: map[model.Key]*clientConn{},
		sources:      map[model.Key]*clientConn{},
	}
	s.endpoints[endpoint] = dst
	return dst
}

func (s *clientsControlServer) removeByClients(fcs *endpointServer) {
	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()

	fcs.mu.Lock()
	defer fcs.mu.Unlock()

	if fcs.empty() {
		delete(s.endpoints, fcs.endpoint)
	}
}

func (s *clientsControlServer) addDestination(conn *clientConn) *endpointServer {
	dst := s.getByEndpoint(conn.auth.endpoint)

	dst.mu.Lock()
	defer dst.mu.Unlock()

	dst.destinations[conn.auth.key] = conn

	return dst
}

func (s *clientsControlServer) removeDestination(fcs *endpointServer, conn *clientConn) {
	if fcs.removeDestination(conn) {
		s.removeByClients(fcs)
	}
}

func (s *clientsControlServer) addSource(conn *clientConn) *endpointServer {
	target := s.getByEndpoint(conn.auth.endpoint)

	target.mu.Lock()
	defer target.mu.Unlock()

	target.sources[conn.auth.key] = conn

	return target
}

func (s *clientsControlServer) removeSource(fcs *endpointServer, conn *clientConn) {
	if fcs.removeSource(conn) {
		s.removeByClients(fcs)
	}
}

type clientConn struct {
	server *clientsControlServer
	conn   *quic.Conn
	logger *slog.Logger

	auth *clientAuth
}

func (c *clientConn) run(ctx context.Context) {
	defer func() {
		if err := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(c.logger, "error closing connection", "err", err)
		}
	}()
	c.logger.Debug("new client connection", "proto", c.conn.ConnectionState().TLS.NegotiatedProtocol, "remote", c.conn.RemoteAddr())

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
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing check client stream", "err", err)
		}
	}()

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

	return quicc.WaitLogRTTStats(ctx, c.conn, c.logger)
}

func (c *clientConn) runSource(ctx context.Context) error {
	fcs := c.server.addSource(c)
	defer c.server.removeSource(fcs, c)

	g := reliable.NewGroup(ctx)

	g.Go(func(ctx context.Context) error {
		return quicc.WaitLogRTTStats(ctx, c.conn, c.logger)
	})

	g.Go(func(ctx context.Context) error {
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

func (c *clientConn) runSourceStream(ctx context.Context, stream *quic.Stream, fcs *endpointServer) {
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing source stream", "err", err)
		}
	}()

	if err := c.runSourceStreamErr(ctx, stream, fcs); err != nil {
		c.logger.Debug("error while running source", "err", err)
	}
}

func (c *clientConn) runSourceStreamErr(ctx context.Context, stream *quic.Stream, fcs *endpointServer) error {
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

func (c *clientConn) connect(ctx context.Context, stream *quic.Stream, fcs *endpointServer, req *pbconnect.Request) error {
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

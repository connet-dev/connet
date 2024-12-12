package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type clientAuth struct {
	fwd         model.Forward
	destination bool
	source      bool
}

type clientsServer struct {
	tlsConf *tls.Config
	auth    func(serverName string, certs []*x509.Certificate) *clientAuth

	destinations   map[model.Forward]map[certc.Key]*clientConn
	destinationsMu sync.RWMutex

	logger *slog.Logger
}

func (s *clientsServer) addDestinations(conn *clientConn) {
	s.destinationsMu.Lock()
	defer s.destinationsMu.Unlock()

	fwdDest := s.destinations[conn.fwd]
	if fwdDest == nil {
		fwdDest = map[certc.Key]*clientConn{}
		s.destinations[conn.fwd] = fwdDest
	}
	fwdDest[conn.key] = conn
}

func (s *clientsServer) removeDestinations(conn *clientConn) {
	s.destinationsMu.Lock()
	defer s.destinationsMu.Unlock()

	fwdDest := s.destinations[conn.fwd]
	delete(fwdDest, conn.key)
	if len(fwdDest) == 0 {
		delete(s.destinations, conn.fwd)
	}
}

func (s *clientsServer) findDestinations(fwd model.Forward) []*clientConn {
	s.destinationsMu.RLock()
	defer s.destinationsMu.RUnlock()

	fwdDest := s.destinations[fwd]
	if fwdDest == nil {
		return nil
	}
	return slices.Collect(maps.Values(fwdDest))
}

func (s *clientsServer) run(ctx context.Context, tr *quic.Transport) error {
	l, err := tr.Listen(s.tlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return kleverr.Ret(err)
	}
	defer l.Close()

	s.logger.Info("waiting for connections")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				err = context.Cause(ctx)
			}
			s.logger.Warn("accept error", "err", err)
			return kleverr.Ret(err)
		}
		s.logger.Info("client connected", "local", conn.LocalAddr(), "remote", conn.RemoteAddr())

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
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (c *clientConn) runErr(ctx context.Context) error {
	serverName := c.conn.ConnectionState().TLS.ServerName
	certs := c.conn.ConnectionState().TLS.PeerCertificates
	auth := c.server.auth(serverName, certs)
	if auth == nil {
		return c.conn.CloseWithError(1, "no auth")
	}

	switch {
	case auth.destination:
		c.fwd = auth.fwd
		c.key = certc.NewKey(certs[0])

		c.server.addDestinations(c)
		defer c.server.removeDestinations(c)

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

		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			go c.runSourceStream(ctx, stream)
		}
	default:
		return kleverr.Newf("not a destination or a source")
	}
}

func (c *clientConn) runDestinationStream(ctx context.Context, stream quic.Stream) error {
	defer stream.Close()

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

func (c *clientConn) runSourceStream(ctx context.Context, stream quic.Stream) error {
	defer stream.Close()

	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Connect != nil:
		return c.connect(ctx, stream)
	case req.Heartbeat != nil:
		return c.heartbeat(ctx, stream, req.Heartbeat)
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *clientConn) connect(ctx context.Context, stream quic.Stream) error {
	// TODO get destination only once
	dests := c.server.findDestinations(c.fwd)
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
		}
	})

	return g.Wait()
}

func (c *clientConn) unknown(ctx context.Context, stream quic.Stream, req *pbc.Request) error {
	c.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(stream, &pbc.Response{Error: err})
}

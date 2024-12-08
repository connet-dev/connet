package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"maps"
	"net"
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

type Config struct {
	Addr   *net.UDPAddr
	Cert   tls.Certificate
	Auth   Authenticator
	Logger *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	s := &Server{
		addr: cfg.Addr,
		auth: cfg.Auth,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cfg.Cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			NextProtos:   []string{"connet-relay"},
		},
		logger: cfg.Logger.With("relay", cfg.Addr),

		destinations: map[model.Forward]map[certc.Key]*relayConn{},
	}
	s.tlsConf.GetConfigForClient = s.tlsConfigWithClientCA

	return s, nil
}

type Server struct {
	addr    *net.UDPAddr
	auth    Authenticator
	tlsConf *tls.Config
	logger  *slog.Logger

	destinations   map[model.Forward]map[certc.Key]*relayConn
	destinationsMu sync.RWMutex
}

func (s *Server) addDestinations(conn *relayConn) {
	s.destinationsMu.Lock()
	defer s.destinationsMu.Unlock()

	fwdDest := s.destinations[conn.auth.Forward()]
	if fwdDest == nil {
		fwdDest = map[certc.Key]*relayConn{}
		s.destinations[conn.auth.Forward()] = fwdDest
	}
	fwdDest[conn.key] = conn
}

func (s *Server) removeDestinations(conn *relayConn) {
	s.destinationsMu.Lock()
	defer s.destinationsMu.Unlock()

	fwdDest := s.destinations[conn.auth.Forward()]
	delete(fwdDest, conn.key)
	if len(fwdDest) == 0 {
		delete(s.destinations, conn.auth.Forward())
	}
}

func (s *Server) findDestinations(fwd model.Forward) []*relayConn {
	s.destinationsMu.RLock()
	defer s.destinationsMu.RUnlock()

	fwdDest := s.destinations[fwd]
	if fwdDest == nil {
		return nil
	}
	return slices.Collect(maps.Values(fwdDest))
}

func (s *Server) tlsConfigWithClientCA(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	certs, cas := s.auth.TLSConfig(chi.ServerName)

	cfg := s.tlsConf.Clone()
	cfg.Certificates = certs
	cfg.ClientCAs = cas
	return cfg, nil
}

func (s *Server) Run(ctx context.Context) error {
	s.logger.Debug("start udp listener")
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer conn.Close()

	s.logger.Debug("start quic listener")
	tr := &quic.Transport{
		Conn: conn,
		// TODO review other options
	}
	defer tr.Close()

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

		rc := &relayConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go rc.run(ctx)
	}
}

type relayConn struct {
	server *Server
	conn   quic.Connection
	logger *slog.Logger

	auth Authentication
	key  certc.Key
}

func (c *relayConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (c *relayConn) runErr(ctx context.Context) error {
	serverName := c.conn.ConnectionState().TLS.ServerName
	certs := c.conn.ConnectionState().TLS.PeerCertificates
	if auth := c.server.auth.Authenticate(serverName, certs); auth == nil {
		c.conn.CloseWithError(1, "auth failed")
		return nil
	} else {
		c.auth = auth
		c.key = certc.NewKey(certs[0])
	}

	switch {
	case c.auth.IsDestination():
		c.server.addDestinations(c)
		defer c.server.removeDestinations(c)

		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			go c.runDestinationStream(ctx, stream)
		}
	case c.auth.IsSource():
		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			go c.runSourceStream(ctx, stream)
		}
	default:
		return kleverr.Newf("invalid authentication, not destination or source")
	}
}

func (c *relayConn) runDestinationStream(ctx context.Context, stream quic.Stream) error {
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

func (c *relayConn) runSourceStream(ctx context.Context, stream quic.Stream) error {
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

func (c *relayConn) connect(ctx context.Context, stream quic.Stream) error {
	// TODO get destination only once
	dests := c.server.findDestinations(c.auth.Forward())
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

func (c *relayConn) connectDestination(ctx context.Context, srcStream quic.Stream, dest *relayConn) error {
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

	c.logger.Debug("joining conns", "forward", c.auth.Forward())
	err = netc.Join(ctx, srcStream, dstStream)
	c.logger.Debug("disconnected conns", "forward", c.auth.Forward(), "err", err)
	return nil
}

func (c *relayConn) heartbeat(ctx context.Context, stream quic.Stream, hbt *pbc.Heartbeat) error {
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

func (c *relayConn) unknown(ctx context.Context, stream quic.Stream, req *pbc.Request) error {
	c.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(stream, &pbc.Response{Error: err})
}

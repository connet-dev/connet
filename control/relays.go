package control

import (
	"context"
	"crypto/x509"
	"log/slog"
	"maps"
	"sync"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type RelayAuthenticator interface {
	Authenticate(token string) (RelayAuthentication, error)
}

type RelayAuthentication interface {
	Allow(fwd model.Forward) bool
}

type relayServer struct {
	auth   RelayAuthenticator
	logger *slog.Logger

	requests   chan relayRequest
	forwards   map[model.Forward]*relayForward
	forwardsMu sync.RWMutex
}

type relayRequest struct {
	fwd         model.Forward
	destination *x509.Certificate
	source      *x509.Certificate
}

type relayForward struct {
	servers *notify.V[map[model.HostPort]*x509.Certificate]
}

func (s *relayServer) createForward(fwd model.Forward) *relayForward {
	if srv := s.getForward(fwd); srv != nil {
		return srv
	}

	s.forwardsMu.Lock()
	defer s.forwardsMu.Unlock()

	if srv := s.forwards[fwd]; srv != nil {
		return srv
	}

	srv := &relayForward{
		servers: notify.NewEmpty[map[model.HostPort]*x509.Certificate](),
	}
	s.forwards[fwd] = srv
	return srv
}

func (s *relayServer) getForward(fwd model.Forward) *relayForward {
	s.forwardsMu.RLock()
	defer s.forwardsMu.RUnlock()

	return s.forwards[fwd]
}

func (s *relayServer) Destination(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
	notify func(map[model.HostPort]*x509.Certificate) error) error {
	srv := s.createForward(fwd)
	s.requests <- relayRequest{fwd: fwd, destination: cert}
	return srv.servers.Listen(ctx, notify)
}

func (s *relayServer) Source(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
	notify func(map[model.HostPort]*x509.Certificate) error) error {
	srv := s.createForward(fwd)
	s.requests <- relayRequest{fwd: fwd, source: cert}
	return srv.servers.Listen(ctx, notify)
}

func (s *relayServer) handle(ctx context.Context, conn quic.Connection) error {
	rc := &relayConn{
		server: s,
		conn:   conn,
		logger: s.logger,
	}
	go rc.run(ctx)
	return nil
}

type relayConn struct {
	server *relayServer
	conn   quic.Connection
	logger *slog.Logger

	auth     RelayAuthentication
	hostport model.HostPort
}

func (c *relayConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (c *relayConn) runErr(ctx context.Context) error {
	if auth, hp, err := c.authenticate(ctx); err != nil {
		c.conn.CloseWithError(1, "auth failed")
		return kleverr.Ret(err)
	} else {
		c.auth = auth
		c.hostport = hp
		c.logger = c.logger.With("relay", "???")
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return c.runForwards(ctx) })
	g.Go(func() error { return c.runClients(ctx) })

	return g.Wait()
}

var retRelayAuth = kleverr.Ret2[RelayAuthentication, model.HostPort]

func (c *relayConn) authenticate(ctx context.Context) (RelayAuthentication, model.HostPort, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return retRelayAuth(err)
	}
	defer authStream.Close()

	req := &pbs.RelayAuth{}
	if err := pb.Read(authStream, req); err != nil {
		return retRelayAuth(err)
	}

	auth, err := c.server.auth.Authenticate(req.Token)
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "Invalid or unknown token")
		if err := pb.Write(authStream, &pbs.RelayAuthResp{Error: err}); err != nil {
			return retRelayAuth(err)
		}
		return retRelayAuth(err)
	}

	if err := pb.Write(authStream, &pbs.RelayAuthResp{}); err != nil {
		return retRelayAuth(err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr())
	return auth, model.NewHostPortFromPB(req.Addr), nil
}

func (c *relayConn) runForwards(ctx context.Context) error {
	stream, err := c.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case req := <-c.server.requests:
			var dst, src *pb.Forward
			var cert *x509.Certificate

			switch {
			case req.destination != nil:
				dst = req.fwd.PB()
				cert = req.destination
			case req.source != nil:
				src = req.fwd.PB()
				cert = req.source
			default:
				continue
			}

			if err := pb.Write(stream, &pbs.RelayClients{
				Changes: []*pbs.RelayClients_Change{{
					Destination:       dst,
					Source:            src,
					ClientCertificate: cert.Raw,
					Change:            pbs.RelayChange_ChangePut,
				}},
			}); err != nil {
				return err
			}
		}
	}
}

func (c *relayConn) runClients(ctx context.Context) error {
	stream, err := c.conn.AcceptUniStream(ctx)
	if err != nil {
		return err
	}

	for {
		req := &pbs.RelayServers{}
		if err := pb.Read(stream, req); err != nil {
			return err
		}

		for _, change := range req.Changes {
			srv := model.NewForwardFromPB(change.Server)
			cert, err := x509.ParseCertificate(change.ServerCertificate)
			if err != nil {
				return err
			}

			srvForward := c.server.getForward(srv)
			srvForward.servers.Update(func(t map[model.HostPort]*x509.Certificate) map[model.HostPort]*x509.Certificate {
				if t == nil {
					t = map[model.HostPort]*x509.Certificate{}
				} else {
					t = maps.Clone(t)
				}

				if change.Change == pbs.RelayChange_ChangeDel {
					delete(t, c.hostport)
				} else {
					t[c.hostport] = cert
				}

				return t
			})
		}
	}
}

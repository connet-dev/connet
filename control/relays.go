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

	relays *notify.V[[]relayRequest]

	forwards   map[model.Forward]*relayForward
	forwardsMu sync.RWMutex
}

type relayRequest struct {
	fwd         model.Forward
	destination *x509.Certificate
	source      *x509.Certificate
	isput       bool
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

func (s *relayServer) notifyRelays(req relayRequest) {
	s.relays.Update(func(t []relayRequest) []relayRequest {
		return append(t, req)
	})
}

func (s *relayServer) Destination(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
	notify func(map[model.HostPort]*x509.Certificate) error) error {
	srv := s.createForward(fwd)
	s.notifyRelays(relayRequest{fwd: fwd, destination: cert, isput: true})
	defer s.notifyRelays(relayRequest{fwd: fwd, destination: cert, isput: false})
	return srv.servers.Listen(ctx, notify)
}

func (s *relayServer) Source(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
	notify func(map[model.HostPort]*x509.Certificate) error) error {
	srv := s.createForward(fwd)
	s.notifyRelays(relayRequest{fwd: fwd, source: cert, isput: true})
	defer s.notifyRelays(relayRequest{fwd: fwd, source: cert, isput: false})
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

	requests, version, err := c.server.relays.GetAny(ctx)
	if err != nil {
		return err
	}

	for {
		c.logger.Debug("sending requests", "version", version, "req", requests)
		out := &pbs.RelayClients{}
		for _, req := range requests {
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

			change := pbs.RelayChange_ChangeDel
			if req.isput {
				change = pbs.RelayChange_ChangePut
			}
			out.Changes = append(out.Changes, &pbs.RelayClients_Change{
				Destination:       dst,
				Source:            src,
				ClientCertificate: cert.Raw,
				Change:            change,
			})
		}

		if err := pb.Write(stream, out); err != nil {
			return err
		}

		nextRequests, nextVersion, err := c.server.relays.Get(ctx, version)
		if err != nil {
			return err
		}
		requests = nextRequests[version+1:]
		version = nextVersion
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

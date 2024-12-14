package control

import (
	"context"
	"crypto/x509"
	"log/slog"
	"sync"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/logc"
	"github.com/keihaya-com/connet/model"
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

	relays logc.KV[relayKey, relayValue]

	forwards   map[model.Forward]*relayForward
	forwardsMu sync.RWMutex
}

type relayKey struct {
	fwd         model.Forward
	destination certc.Key
	source      certc.Key
}

type relayValue struct {
	destination *x509.Certificate
	source      *x509.Certificate
}

type relayForward struct {
	serverLog logc.KV[model.HostPort, *x509.Certificate]
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
		serverLog: logc.NewMemoryKVLog[model.HostPort, *x509.Certificate](),
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
	notifyFn func(map[model.HostPort]*x509.Certificate) error) error {
	srv := s.createForward(fwd)

	key := relayKey{fwd: fwd, destination: certc.NewKey(cert)}
	val := relayValue{destination: cert}
	s.relays.Put(key, val)
	defer s.relays.PutDel(key, val)

	return srv.serverLog.Listen(ctx, notifyFn)
}

func (s *relayServer) Source(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
	notifyFn func(map[model.HostPort]*x509.Certificate) error) error {
	srv := s.createForward(fwd)

	key := relayKey{fwd: fwd, source: certc.NewKey(cert)}
	val := relayValue{source: cert}
	s.relays.Put(key, val)
	defer s.relays.PutDel(key, val)

	return srv.serverLog.Listen(ctx, notifyFn)
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
		c.logger = c.logger.With("relay", hp)
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
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		req := &pbs.RelayClientsReq{}
		if err := pb.Read(stream, req); err != nil {
			return err
		}

		var msgs []logc.Message[relayKey, relayValue]
		var nextOffset int64
		if req.Offset == logc.OffsetOldest {
			msgs, nextOffset, err = c.server.relays.Snapshot(ctx)
			c.logger.Debug("sending initial relay changes", "offset", nextOffset, "changes", len(msgs))
		} else {
			msgs, nextOffset, err = c.server.relays.Consume(ctx, req.Offset)
			c.logger.Debug("sending delta relay changes", "offset", nextOffset, "changes", len(msgs))
		}
		if err != nil {
			return err
		}

		// if len(msgs) == 0 && offset >= 0 && offset < nextOffset {
		// TODO we are too far off and potentially have missed messages
		// }

		resp := &pbs.RelayClients{Offset: nextOffset}

		for _, msg := range msgs {
			if !c.auth.Allow(msg.Key.fwd) {
				continue
			}

			var dst, src *pb.Forward
			var cert *x509.Certificate

			switch {
			case msg.Key.destination.IsValid():
				dst = msg.Key.fwd.PB()
				cert = msg.Value.destination
			case msg.Key.source.IsValid():
				src = msg.Key.fwd.PB()
				cert = msg.Value.source
			default:
				continue
			}

			change := pbs.RelayChange_ChangePut
			if msg.Delete {
				change = pbs.RelayChange_ChangeDel
			}
			resp.Changes = append(resp.Changes, &pbs.RelayClients_Change{
				Destination:       dst,
				Source:            src,
				ClientCertificate: cert.Raw,
				Change:            change,
			})
		}

		if err := pb.Write(stream, resp); err != nil {
			return err
		}
	}
}

func (c *relayConn) runClients(ctx context.Context) error {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	offset := logc.OffsetOldest
	for {
		req := &pbs.RelayServersReq{
			Offset: offset,
		}
		if err := pb.Write(stream, req); err != nil {
			return err
		}

		resp := &pbs.RelayServers{}
		if err := pb.Read(stream, resp); err != nil {
			return err
		}

		for _, change := range resp.Changes {
			srv := model.NewForwardFromPB(change.Server)

			srvForward := c.server.getForward(srv)
			if change.Change == pbs.RelayChange_ChangeDel {
				srvForward.serverLog.Del(c.hostport)
			} else {
				cert, err := x509.ParseCertificate(change.ServerCertificate)
				if err != nil {
					return err
				}

				srvForward.serverLog.Put(c.hostport, cert)
			}
		}

		offset = resp.Offset
	}
}

package control

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"maps"
	"sync"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/logc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbr"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type RelayAuthenticator interface {
	Authenticate(token string) (RelayAuthentication, error)
}

type RelayAuthentication interface {
	Allow(fwd model.Forward) bool
}

type relayServer struct {
	id     ksuid.KSUID
	auth   RelayAuthenticator
	logger *slog.Logger

	relayClients logc.KV[relayClientKey, relayClientValue]
	relayServers logc.KV[relayServerKey, relayServerValue]
	relayOffsets logc.KV[model.HostPort, int64]

	forwardsCache  map[model.Forward]map[model.HostPort]*x509.Certificate
	forwardsOffset int64
	forwardsMu     sync.RWMutex
}

type relayClientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	Key     certc.Key     `json:"key"`
}

type relayClientValue struct {
	Cert []byte `json:"cert"`
}

type relayServerKey struct {
	Forward  model.Forward  `json:"forward"`
	Hostport model.HostPort `json:"hostport"`
}

type relayServerValue struct {
	Cert []byte `json:"cert"`
}

func (s *relayServer) getForward(fwd model.Forward) (map[model.HostPort]*x509.Certificate, int64) {
	s.forwardsMu.RLock()
	defer s.forwardsMu.RUnlock()

	return maps.Clone(s.forwardsCache[fwd]), s.forwardsOffset
}

func (s *relayServer) Client(ctx context.Context, fwd model.Forward, role model.Role, cert *x509.Certificate,
	notifyFn func(map[model.HostPort]*x509.Certificate) error) error {

	key := relayClientKey{Forward: fwd, Role: role, Key: certc.NewKey(cert)}
	val := relayClientValue{Cert: cert.Raw}
	s.relayClients.Put(key, val)
	defer s.relayClients.Del(key)

	return s.listen(ctx, fwd, notifyFn)
}

func (s *relayServer) listen(ctx context.Context, fwd model.Forward,
	notifyFn func(map[model.HostPort]*x509.Certificate) error) error {

	servers, offset := s.getForward(fwd)
	if len(servers) > 0 {
		if err := notifyFn(servers); err != nil {
			return err
		}
	}

	for {
		msgs, nextOffset, err := s.relayServers.Consume(ctx, offset)
		if err != nil {
			return err
		}

		var changed bool
		for _, msg := range msgs {
			if msg.Key.Forward != fwd {
				continue
			}

			if msg.Delete {
				delete(servers, msg.Key.Hostport)
			} else {
				if servers == nil {
					servers = map[model.HostPort]*x509.Certificate{}
				}
				cert, err := x509.ParseCertificate(msg.Value.Cert) // TODO do this once on deser
				if err != nil {
					return err
				}
				servers[msg.Key.Hostport] = cert
			}
			changed = true
		}

		offset = nextOffset

		if changed {
			if err := notifyFn(servers); err != nil {
				return err
			}
		}
	}
}

func (s *relayServer) run(ctx context.Context) error {
	update := func(msg logc.Message[relayServerKey, relayServerValue]) error {
		s.forwardsMu.Lock()
		defer s.forwardsMu.Unlock()

		srv := s.forwardsCache[msg.Key.Forward]
		if msg.Delete {
			delete(srv, msg.Key.Hostport)
			if len(srv) == 0 {
				delete(s.forwardsCache, msg.Key.Forward)
			}
		} else {
			if srv == nil {
				srv = map[model.HostPort]*x509.Certificate{}
				s.forwardsCache[msg.Key.Forward] = srv
			}
			cert, err := x509.ParseCertificate(msg.Value.Cert) // TODO do this once on deser
			if err != nil {
				return err
			}
			srv[msg.Key.Hostport] = cert
		}

		s.forwardsOffset = msg.Offset + 1
		return nil
	}

	for {
		s.forwardsMu.RLock()
		offset := s.forwardsOffset
		s.forwardsMu.RUnlock()

		msgs, nextOffset, err := s.relayServers.Consume(ctx, offset)
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			if err := update(msg); err != nil {
				return err
			}
		}

		s.forwardsMu.Lock()
		s.forwardsOffset = nextOffset
		s.forwardsMu.Unlock()
	}
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

func (s *relayServer) getRelayOffset(hp model.HostPort) (int64, error) {
	offset, err := s.relayOffsets.Get(hp)
	switch {
	case errors.Is(err, logc.ErrNotFound):
		return logc.OffsetOldest, nil
	case err != nil:
		return logc.OffsetInvalid, err
	default:
		return offset, nil
	}
}

func (s *relayServer) setRelayOffset(hp model.HostPort, offset int64) error {
	return s.relayOffsets.Put(hp, offset)
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

	g.Go(func() error { return c.runRelayClients(ctx) })
	g.Go(func() error { return c.runRelayServers(ctx) })

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

	req := &pbr.AuthenticateReq{}
	if err := pb.Read(authStream, req); err != nil {
		return retRelayAuth(err)
	}

	auth, err := c.server.auth.Authenticate(req.Token)
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "Invalid or unknown token")
		if err := pb.Write(authStream, &pbr.AuthenticateResp{Error: err}); err != nil {
			return retRelayAuth(err)
		}
		return retRelayAuth(err)
	}

	if err := pb.Write(authStream, &pbr.AuthenticateResp{
		ControlId: c.server.id.String(),
	}); err != nil {
		return retRelayAuth(err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr())
	return auth, model.NewHostPortFromPB(req.Addr), nil
}

func (c *relayConn) runRelayClients(ctx context.Context) error {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		req := &pbr.ClientsReq{}
		if err := pb.Read(stream, req); err != nil {
			return err
		}

		var msgs []logc.Message[relayClientKey, relayClientValue]
		var nextOffset int64
		if req.Offset == logc.OffsetOldest {
			msgs, nextOffset, err = c.server.relayClients.Snapshot()
			c.logger.Debug("sending initial relay changes", "offset", nextOffset, "changes", len(msgs))
		} else {
			msgs, nextOffset, err = c.server.relayClients.Consume(ctx, req.Offset)
			c.logger.Debug("sending delta relay changes", "offset", nextOffset, "changes", len(msgs))
		}
		if err != nil {
			return err
		}

		// if len(msgs) == 0 && offset >= 0 && offset < nextOffset {
		// TODO we are too far off and potentially have missed messages
		// }

		resp := &pbr.ClientsResp{Offset: nextOffset}

		for _, msg := range msgs {
			if !c.auth.Allow(msg.Key.Forward) {
				continue
			}

			change := &pbr.ClientsResp_Change{
				Forward:        msg.Key.Forward.PB(),
				Role:           msg.Key.Role.PB(),
				CertificateKey: msg.Key.Key.String(),
			}

			if msg.Delete {
				change.Change = pbr.ChangeType_ChangeDel
			} else {
				change.Change = pbr.ChangeType_ChangePut
				change.Certificate = msg.Value.Cert
			}

			resp.Changes = append(resp.Changes, change)
		}

		if err := pb.Write(stream, resp); err != nil {
			return err
		}
	}
}

func (c *relayConn) runRelayServers(ctx context.Context) error {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		offset, err := c.server.getRelayOffset(c.hostport)
		if err != nil {
			return err
		}

		req := &pbr.ServersReq{
			Offset: offset,
		}
		if err := pb.Write(stream, req); err != nil {
			return err
		}

		resp := &pbr.ServersResp{}
		if err := pb.Read(stream, resp); err != nil {
			return err
		}

		for _, change := range resp.Changes {
			key := relayServerKey{
				Forward:  model.NewForwardFromPB(change.Server),
				Hostport: c.hostport,
			}

			switch change.Change {
			case pbr.ChangeType_ChangePut:
				cert, err := x509.ParseCertificate(change.ServerCertificate)
				if err != nil {
					return err
				}
				if err := c.server.relayServers.Put(key, relayServerValue{cert.Raw}); err != nil {
					return err
				}
			case pbr.ChangeType_ChangeDel:
				if err := c.server.relayServers.Del(key); err != nil {
					return err
				}
			default:
				return kleverr.New("unknown change")
			}
		}

		if err := c.server.setRelayOffset(c.hostport, resp.Offset); err != nil {
			return err
		}
	}
}

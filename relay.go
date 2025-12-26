package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pbclientrelay"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/slogc"
	"github.com/quic-go/quic-go"
)

var errRelayRemoved = errors.New("relay removed")

type relayID string

type relay struct {
	local *peer

	serverID        relayID
	serverHostports []model.HostPort
	serverConf      atomic.Pointer[serverTLSConfig]

	cancel context.CancelCauseFunc
	logger *slog.Logger
}

func runRelay(ctx context.Context, local *peer, id relayID, hps []model.HostPort, serverConf *serverTLSConfig, logger *slog.Logger) *relay {
	ctx, cancel := context.WithCancelCause(ctx)
	r := &relay{
		local: local,

		serverID:        id,
		serverHostports: hps,

		cancel: cancel,
		logger: logger.With("relay", id, "addrs", hps),
	}
	r.serverConf.Store(serverConf)
	go r.run(ctx)
	return r
}

func (r *relay) run(ctx context.Context) {
	if err := r.runErr(ctx); err != nil {
		r.logger.Debug("error running relay", "err", err)
	}
}

func (r *relay) runErr(ctx context.Context) error {
	boff := reliable.MinBackoff
	for {
		conn, err := r.connectAny(ctx)
		if err != nil {
			r.logger.Debug("could not connect relay", "err", err)
			if errors.Is(err, context.Canceled) {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(boff):
				boff = reliable.NextBackoff(boff)
			}
			continue
		}
		boff = reliable.MinBackoff

		if err := r.keepalive(ctx, conn); err != nil {
			r.logger.Debug("disconnected relay", "err", err)
		}
	}
}

func (r *relay) connectAny(ctx context.Context) (*quic.Conn, error) {
	for _, hp := range r.serverHostports {
		if conn, err := r.connect(ctx, hp); err != nil {
			r.logger.Debug("cannot connect relay", "hostport", hp, "err", err)
		} else {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("cannot connect to relay: %s", r.serverID)
}

func (r *relay) connect(ctx context.Context, hp model.HostPort) (*quic.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", hp.String())
	if err != nil {
		return nil, err
	}

	cfg := r.serverConf.Load()
	r.logger.Debug("dialing relay", "addr", addr, "server", cfg.name, "cert", cfg.key)
	conn, err := r.local.direct.transport.Dial(ctx, addr, &tls.Config{
		Certificates: []tls.Certificate{r.local.clientCert},
		RootCAs:      cfg.cas,
		ServerName:   cfg.name,
		NextProtos:   model.ConnectRelayControlNextProtos,
	}, quicc.StdConfig)
	if err != nil {
		return nil, err
	}

	if err := r.check(ctx, conn); err != nil {
		cerr := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_ConnectionCheckFailed), "connection check failed")
		return nil, errors.Join(err, cerr)
	}
	return conn, nil
}

func (r *relay) check(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(r.logger, "error closing check stream", "err", err)
		}
	}()

	if err := proto.Write(stream, &pbconnect.Request{}); err != nil {
		return err
	}
	if _, err := pbconnect.ReadResponse(stream); err != nil {
		return err
	}

	return nil
}

func (r *relay) keepalive(ctx context.Context, conn *quic.Conn) error {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_RelayKeepaliveClosed), "keepalive closed"); err != nil {
			slogc.Fine(r.logger, "error closing connection", "err", err)
		}
	}()

	r.local.addRelayConn(r.serverID, conn)
	defer r.local.removeRelayConn(r.serverID)

	return quicc.WaitLogRTTStats(ctx, conn, r.logger)
}

type directRelay struct {
	local *peer

	serverID        relayID
	serverHostports []model.HostPort
	serverConf      atomic.Pointer[serverTLSConfig]

	cancel context.CancelFunc
	logger *slog.Logger
}

func runDirectRelay(ctx context.Context, local *peer, id relayID, hps []model.HostPort, serverConf *serverTLSConfig, logger *slog.Logger) *directRelay {
	ctx, cancel := context.WithCancel(ctx)
	r := &directRelay{
		local:           local,
		serverID:        id,
		serverHostports: hps,
		cancel:          cancel,
		logger:          logger.With("direct-relay", id, "addrs", hps),
	}
	r.serverConf.Store(serverConf)
	go r.run(ctx)
	return r
}

func (r *directRelay) run(ctx context.Context) {
	if err := r.runErr(ctx); err != nil {
		r.logger.Debug("error while running direct relay", "err", err)
	}
}

func (r *directRelay) runErr(ctx context.Context) error {
	boff := reliable.MinBackoff
	for {
		conn, err := r.connectAny(ctx)
		if err != nil {
			r.logger.Debug("could not connect direct relay", "err", err)
			if errors.Is(err, context.Canceled) {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(boff):
				boff = reliable.NextBackoff(boff)
			}
			continue
		}
		boff = reliable.MinBackoff

		if err := r.runRelay(ctx, conn); err != nil {
			r.logger.Debug("disconnected direct relay", "err", err)
		}
	}
}

func (r *directRelay) connectAny(ctx context.Context) (*quic.Conn, error) {
	for _, hp := range r.serverHostports {
		if conn, err := r.connect(ctx, hp); err != nil {
			r.logger.Debug("cannot connect direct relay", "hostport", hp, "err", err)
		} else {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("cannot connect to direct relay: %s", r.serverID)
}

func (r *directRelay) connect(ctx context.Context, hp model.HostPort) (*quic.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", hp.String())
	if err != nil {
		return nil, err
	}

	cfg := r.serverConf.Load()
	r.logger.Debug("dialing direct relay", "addr", addr, "server", cfg.name, "cert", cfg.key)
	conn, err := r.local.direct.transport.Dial(ctx, addr, &tls.Config{
		Certificates: []tls.Certificate{r.local.clientCert},
		RootCAs:      cfg.cas,
		ServerName:   cfg.name,
		NextProtos:   model.ConnectRelayDirectNextProtos,
	}, quicc.StdConfig)
	if err != nil {
		return nil, err
	}

	if err := r.check(ctx, conn); err != nil {
		cerr := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_ConnectionCheckFailed), "connection check failed")
		return nil, errors.Join(err, cerr)
	}
	return conn, nil
}

func (r *directRelay) check(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(r.logger, "error closing check stream", "err", err)
		}
	}()

	if err := proto.Write(stream, &pbclientrelay.AuthenticateReq{
		ClientId:     "", // TODO peer id
		BuildVersion: model.BuildVersion(),
	}); err != nil {
		return fmt.Errorf("cannot write auth request: %w", err)
	}

	resp := &pbclientrelay.AuthenticateResp{}
	if err := proto.Read(stream, resp); err != nil {
		return fmt.Errorf("cannot read auth response: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("error in auth response: %w", resp.Error)
	}

	return nil
}

func (r *directRelay) runRelay(ctx context.Context, conn *quic.Conn) error {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_RelayKeepaliveClosed), "keepalive closed"); err != nil {
			slogc.Fine(r.logger, "error closing connection", "err", err)
		}
	}()

	r.local.addActiveConn("*", peerRelayIncoming, string(r.serverID), conn)
	defer r.local.removeActiveConn("*", peerRelayIncoming, string(r.serverID))

	return r.reserve(ctx, conn)
}

func (r *directRelay) reserve(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("announce open stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(r.logger, "error closing announce stream", "err", err)
		}
	}()

	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(stream))

	g.Go(func(ctx context.Context) error {
		defer r.logger.Debug("completed relay announce")

		var activePeers []*pbclient.RemotePeer
		return r.local.peers.Listen(ctx, func(remotes []*pbclient.RemotePeer) error {
			if slices.EqualFunc(activePeers, remotes, func(l, r *pbclient.RemotePeer) bool {
				return l.Id == r.Id
			}) {
				return nil
			}
			activePeers = remotes

			r.logger.Debug("updated announce", "peers", len(remotes))
			if err := proto.Write(stream, &pbclientrelay.ReserveReq{
				Peers: iterc.MapSlice(remotes, func(remote *pbclient.RemotePeer) *pbclientrelay.Peer {
					return &pbclientrelay.Peer{
						Id:                remote.Id,
						ClientCertificate: remote.Peer.ClientCertificate,
					}
				}),
			}); err != nil {
				return fmt.Errorf("direct relay write: %w", err)
			}
			return nil
		})
	})

	g.Go(func(ctx context.Context) error {
		defer r.local.removeDirectPeerRelay(r.serverID)
		for {
			resp := &pbclientrelay.ReserveResp{}
			if err := proto.Read(stream, resp); err != nil {
				return fmt.Errorf("direct relay read: %w", err)
			} else if resp.Error != nil {
				return fmt.Errorf("direct relay resp: %w", err)
			}

			cert, err := x509.ParseCertificate(resp.ServerCertificate)
			if err != nil {
				return fmt.Errorf("direct relay cert: %w", err)
			}
			r.local.addDirectPeerRelay(&pbclient.PeerDirectRelay{
				Id:                 string(r.serverID),
				Addresses:          iterc.MapSlice(r.serverHostports, model.HostPort.PB),
				ConnectCertificate: cert.Raw,
			})
		}
	})

	return g.Wait()
}

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type relayID string

type relayPeer struct {
	local *peer

	serverID        relayID
	serverHostports []model.HostPort
	serverConf      atomic.Pointer[serverTLSConfig]

	closer chan struct{}

	logger *slog.Logger
}

func newRelayPeer(local *peer, id relayID, hps []model.HostPort, serverConf *serverTLSConfig, logger *slog.Logger) *relayPeer {
	r := &relayPeer{
		local:           local,
		serverID:        id,
		serverHostports: hps,
		closer:          make(chan struct{}),
		logger:          logger.With("relay", id, "addrs", hps),
	}
	r.serverConf.Store(serverConf)
	return r
}

func (r *relayPeer) run(ctx context.Context) {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return r.runConn(ctx) })
	g.Go(func() error {
		<-r.closer
		return errPeeringStop
	})

	if err := g.Wait(); err != nil {
		r.logger.Debug("error while running relaying", "err", err)
	}
}

func (r *relayPeer) runConn(ctx context.Context) error {
	boff := netc.MinBackoff
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
				boff = netc.NextBackoff(boff)
			}
			continue
		}
		boff = netc.MinBackoff

		if err := r.keepalive(ctx, conn); err != nil {
			r.logger.Debug("disconnected relay", "err", err)
		}
	}
}

func (r *relayPeer) connectAny(ctx context.Context) (relayConn, error) {
	for _, hp := range r.serverHostports {
		if conn, err := r.connect(ctx, hp); err != nil {
			r.logger.Debug("cannot connet relay", "hostport", hp, "err", err)
		} else {
			// compat: use the first one as "connected relay" since old peers will only look at it anyways
			return relayConn{conn, r.serverHostports[0]}, nil
		}
	}
	return relayConn{}, fmt.Errorf("cannot connect to relay: %s", r.serverID)
}

func (r *relayPeer) connect(ctx context.Context, hp model.HostPort) (quic.Connection, error) {
	addr, err := net.ResolveUDPAddr("udp", hp.String())
	if err != nil {
		return nil, err
	}

	cfg := r.serverConf.Load()
	r.logger.Debug("dialing relay", "addr", addr, "server", cfg.name, "cert", cfg.key)
	conn, err := r.local.direct.transport.Dial(quicc.RTTContext(ctx), addr, &tls.Config{
		Certificates: []tls.Certificate{r.local.clientCert},
		RootCAs:      cfg.cas,
		ServerName:   cfg.name,
		NextProtos:   model.ClientToRelayNextProtos,
	}, quicc.StdConfig)
	if err != nil {
		return nil, err
	}

	if err := r.check(ctx, conn); err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(proto.Error_ConnectionCheckFailed), "connection check failed")
		return nil, err
	}
	return conn, nil
}

func (r *relayPeer) check(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	if err := proto.Write(stream, &pbconnect.Request{}); err != nil {
		return err
	}
	if _, err := pbconnect.ReadResponse(stream); err != nil {
		return err
	}

	return nil
}

func (r *relayPeer) keepalive(ctx context.Context, conn relayConn) error {
	defer conn.conn.CloseWithError(quic.ApplicationErrorCode(proto.Error_RelayKeepaliveClosed), "keepalive closed")

	r.local.addRelayConn(r.serverID, conn)
	defer r.local.removeRelayConn(r.serverID)

	quicc.RTTLogStats(conn.conn, r.logger)
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-conn.conn.Context().Done():
			return context.Cause(conn.conn.Context())
		case <-time.After(30 * time.Second):
			quicc.RTTLogStats(conn.conn, r.logger)
		}
	}
}

func (r *relayPeer) stop() {
	close(r.closer)
}

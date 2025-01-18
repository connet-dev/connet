package client

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type relayPeer struct {
	local *peer

	serverHostport model.HostPort
	serverConf     atomic.Pointer[serverTLSConfig]

	closer chan struct{}

	logger *slog.Logger
}

func newRelayPeer(local *peer, hp model.HostPort, serverConf *serverTLSConfig, logger *slog.Logger) *relayPeer {
	r := &relayPeer{
		local:          local,
		serverHostport: hp,
		closer:         make(chan struct{}),
		logger:         logger.With("relay", hp),
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
		conn, err := r.connect(ctx)
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

func (r *relayPeer) connect(ctx context.Context) (quic.Connection, error) {
	addr, err := net.ResolveUDPAddr("udp", r.serverHostport.String())
	if err != nil {
		return nil, err
	}

	cfg := r.serverConf.Load()
	r.logger.Debug("dialing relay", "addr", addr, "server", cfg.name, "cert", cfg.key)
	conn, err := r.local.direct.transport.Dial(quicc.RTTContext(ctx), addr, &tls.Config{
		Certificates: []tls.Certificate{r.local.clientCert},
		RootCAs:      cfg.cas,
		ServerName:   cfg.name,
		NextProtos:   []string{"connet-relay"},
	}, quicc.StdConfig)
	if err != nil {
		return nil, err
	}

	if err := r.check(ctx, conn); err != nil {
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

	if err := pb.Write(stream, &pbc.Request{}); err != nil {
		return err
	}
	if _, err := pbc.ReadResponse(stream); err != nil {
		return err
	}
	return nil
}

func (r *relayPeer) keepalive(ctx context.Context, conn quic.Connection) error {
	r.local.addRelayConn(r.serverHostport, conn)
	defer r.local.removeRelayConn(r.serverHostport)

	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-conn.Context().Done():
			return context.Cause(conn.Context())
		case <-time.After(10 * time.Second): // TODO 30 sec?
			if rttStats := quicc.RTTStats(conn); rttStats != nil {
				r.logger.Debug("rtt stats", "last", rttStats.LatestRTT(), "smoothed", rttStats.SmoothedRTT())
			}
		}
	}
}

func (r *relayPeer) stop() {
	close(r.closer)
}

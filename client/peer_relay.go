package client

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
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
			r.logger.Debug("could not connect relay", "relay", r.serverHostport, "err", err)
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
			r.logger.Debug("disconnected relay", "relay", r.serverHostport, "err", err)
		}
	}
}

func (r *relayPeer) connect(ctx context.Context) (quic.Connection, error) {
	addr, err := net.ResolveUDPAddr("udp", r.serverHostport.String())
	if err != nil {
		return nil, err
	}

	cfg := r.serverConf.Load()
	r.logger.Debug("dialing relay", "relay", r.serverHostport, "addr", addr, "server", cfg.name, "cert", cfg.key)
	return r.local.direct.transport.Dial(ctx, addr, &tls.Config{
		Certificates: []tls.Certificate{r.local.clientCert},
		RootCAs:      cfg.cas,
		ServerName:   cfg.name,
		NextProtos:   []string{"connet-relay"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
}

func (r *relayPeer) keepalive(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if err := r.heartbeat(ctx, stream); err != nil {
		return err
	}

	r.local.addRelayConn(r.serverHostport, conn)
	defer r.local.removeRelayConn(r.serverHostport)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
		if err := r.heartbeat(ctx, stream); err != nil {
			return err
		}
	}
}

func (r *relayPeer) heartbeat(ctx context.Context, stream quic.Stream) error {
	// TODO setDeadline as additional assurance we are not blocked
	req := &pbc.Heartbeat{Time: timestamppb.Now()}
	if err := pb.Write(stream, &pbc.Request{Heartbeat: req}); err != nil {
		return err
	}
	if resp, err := pbc.ReadResponse(stream); err != nil {
		return err
	} else {
		dur := time.Since(resp.Heartbeat.Time.AsTime())
		r.logger.Debug("relay heartbeat", "dur", dur)
		return nil
	}
}

func (r *relayPeer) stop() {
	close(r.closer)
}

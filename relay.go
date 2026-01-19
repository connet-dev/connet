package connet

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
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclientrelay"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/quic-go/quic-go"
)

var errRelayRemoved = errors.New("relay removed")

type relayID string

type relay struct {
	local *peer

	serverID        relayID
	serverHostports []model.HostPort
	serverConf      atomic.Pointer[relayConfig]

	cancel context.CancelCauseFunc
	logger *slog.Logger
}

type relayConfig struct {
	tls  *serverTLSConfig
	auth []byte
}

func runRelay(ctx context.Context, local *peer, id relayID, hps []model.HostPort, cfg *relayConfig, logger *slog.Logger) *relay {
	ctx, cancel := context.WithCancelCause(ctx)
	r := &relay{
		local: local,

		serverID:        id,
		serverHostports: hps,

		cancel: cancel,
		logger: logger.With("relay", id, "addrs", hps),
	}
	r.serverConf.Store(cfg)
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

	r.logger.Debug("dialing relay", "addr", addr, "server", cfg.tls.name, "cert", cfg.tls.key)
	conn, err := r.local.direct.transport.Dial(ctx, addr, &tls.Config{
		Certificates: []tls.Certificate{r.local.clientCert},
		RootCAs:      cfg.tls.cas,
		ServerName:   cfg.tls.name,
		NextProtos:   iterc.MapVarStrings(model.ConnectRelayV02),
	}, quicc.ClientConfig(r.local.direct.handshakeIdleTimeout))
	if err != nil {
		return nil, err
	}

	if err := r.authenticate(ctx, conn, cfg.auth); err != nil {
		if perr := pberror.GetError(err); perr != nil {
			cerr := conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
			return nil, errors.Join(perr, cerr)
		}
		cerr := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_ConnectionCheckFailed), "connection check failed")
		return nil, errors.Join(err, cerr)
	}
	return conn, nil
}

func (r *relay) authenticate(ctx context.Context, conn *quic.Conn, auth []byte) error {
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
		Authentication: auth,
		Metadata:       r.local.metadata,
		BuildVersion:   model.BuildVersion(),
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

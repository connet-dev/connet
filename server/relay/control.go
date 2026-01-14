package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/certc"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/logc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/pkg/statusc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclientrelay"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/proto/pbrelay"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/nacl/box"
	protobuf "google.golang.org/protobuf/proto"
)

type controlClient struct {
	hostports []model.HostPort
	direct    *certc.Cert
	metadata  string

	controlAddr          *net.UDPAddr
	controlToken         string
	controlTLSConf       *tls.Config
	handshakeIdleTimeout time.Duration

	config logc.KV[ConfigKey, ConfigValue]

	authUnsealKey atomic.Pointer[[32]byte]

	connStatus atomic.Value
	logger     *slog.Logger
}

func newControlClient(cfg Config, direct *certc.Cert, configStore logc.KV[ConfigKey, ConfigValue]) (*controlClient, error) {
	hostports := iterc.FlattenSlice(iterc.MapSlice(cfg.Ingress, func(in Ingress) []model.HostPort {
		return in.Hostports
	}))

	c := &controlClient{
		hostports: hostports,
		direct:    direct,
		metadata:  cfg.Metadata,

		controlAddr:  cfg.ControlAddr,
		controlToken: cfg.ControlToken,
		controlTLSConf: &tls.Config{
			ServerName: cfg.ControlHost,
			RootCAs:    cfg.ControlCAs,
			NextProtos: iterc.MapVarStrings(model.RelayControlV03),
		},
		handshakeIdleTimeout: cfg.HandshakeIdleTimeout,

		config: configStore,

		logger: cfg.Logger.With("client", "relay-control"),
	}
	c.connStatus.Store(statusc.NotConnected)
	return c, nil
}

func (s *controlClient) Authenticate(authReq *pbclientrelay.AuthenticateReq, cert *x509.Certificate) (*clientAuth, error) {
	authUnsealKey := s.authUnsealKey.Load()
	if authUnsealKey == nil {
		return nil, fmt.Errorf("no control verification key")
	}

	decryptNonce := [24]byte(authReq.Authentication)
	authData, ok := box.OpenAfterPrecomputation(nil, authReq.Authentication[24:], &decryptNonce, authUnsealKey)
	if !ok {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "invalid authentication")
	}
	var auth pbrelay.ClientAuthentication
	if err := protobuf.Unmarshal(authData, &auth); err != nil {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "invalid authentication data")
	}
	certKey := model.NewKey(cert)
	if auth.CertificateKey != certKey.String() {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "invalid certificate")
	}

	return &clientAuth{model.EndpointFromPB(auth.Endpoint), model.RoleFromPB(auth.Role), certKey, model.ConnectRelayV02, authReq.Metadata}, nil
}

type TransportsFn func(ctx context.Context) ([]*quic.Transport, error)

func (s *controlClient) run(ctx context.Context, tfn TransportsFn) error {
	return reliable.RunGroup(ctx,
		reliable.Bind(tfn, s.runControl),
		logc.ScheduleCompact(s.config),
	)
}

func (s *controlClient) runControl(ctx context.Context, tfn TransportsFn) error {
	defer s.connStatus.Store(statusc.Disconnected)

	s.logger.Info("connecting to control server", "addr", s.controlAddr, "hostports", s.hostports)
	conn, err := s.connect(ctx, tfn)
	if err != nil {
		return err
	}

	var boff reliable.SpinBackoff
	for {
		if err := s.runConnection(ctx, conn); err != nil {
			s.logger.Error("session ended", "err", err)
			if errors.Is(err, context.Canceled) {
				return err
			}
		}

		if err := boff.Wait(ctx); err != nil {
			return err
		}

		s.logger.Info("reconnecting to control server", "addr", s.controlAddr)
		if conn, err = s.reconnect(ctx, tfn); err != nil {
			return err
		}
	}
}

func (s *controlClient) connect(ctx context.Context, tfn TransportsFn) (*quic.Conn, error) {
	transports, err := tfn(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get transports: %w", err)
	}

	reconnConfig, err := s.config.GetOrDefault(configControlReconnect, ConfigValue{})
	if err != nil {
		return nil, fmt.Errorf("server reconnect get: %w", err)
	}

	for _, transport := range transports {
		if conn, err := s.connectSingle(ctx, transport, reconnConfig); err != nil {
			s.logger.Debug("cannot connect relay control server", "localAddr", transport.Conn.LocalAddr(), "err", err)
		} else {
			return conn, nil
		}
	}

	return nil, fmt.Errorf("could not reach the control server on any of the transports")
}

func (s *controlClient) connectSingle(ctx context.Context, transport *quic.Transport, reconnConfig ConfigValue) (*quic.Conn, error) {
	conn, err := transport.Dial(ctx, s.controlAddr, s.controlTLSConf, quicc.ClientConfig(s.handshakeIdleTimeout))
	if err != nil {
		return nil, fmt.Errorf("cannot dial: %w", err)
	}

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() {
		if err := authStream.Close(); err != nil {
			slogc.Fine(s.logger, "relay control server: close stream error", "localAddr", transport.Conn.LocalAddr(), "err", err)
		}
	}()

	if err := s.authenticate(authStream, reconnConfig); err != nil {
		perr := pberror.GetError(err)
		if perr == nil {
			perr = pberror.NewError(pberror.Code_AuthenticationFailed, "authentication failed")
		}
		cerr := conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
		return nil, errors.Join(perr, cerr)
	}

	return conn, nil
}

func (s *controlClient) authenticate(authStream *quic.Stream, reconnConfig ConfigValue) error {
	relayPk, relaySk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("could not create keys: %w", err)
	}

	if err := proto.Write(authStream, &pbrelay.AuthenticateReq{
		Token:                  s.controlToken,
		Addresses:              model.PBsFromHostPorts(s.hostports),
		ReconnectToken:         reconnConfig.Bytes,
		BuildVersion:           model.BuildVersion(),
		Metadata:               s.metadata,
		ServerCertificate:      s.direct.Raw(),
		RelayAuthenticationKey: relayPk[:],
	}); err != nil {
		return fmt.Errorf("auth write error: %w", err)
	}

	resp := &pbrelay.AuthenticateResp{}
	if err := proto.Read(authStream, resp); err != nil {
		return fmt.Errorf("auth read error: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("remote error: %w", resp.Error)
	}

	controlIDConfig, err := s.config.GetOrDefault(configControlID, ConfigValue{})
	if err != nil {
		return fmt.Errorf("server control id get: %w", err)
	}
	if controlIDConfig.String != "" && controlIDConfig.String != resp.ControlId {
		return fmt.Errorf("unexpected server id, has: %s, resp: %s", controlIDConfig.String, resp.ControlId)
	}
	controlIDConfig.String = resp.ControlId
	if err := s.config.Put(configControlID, controlIDConfig); err != nil {
		return fmt.Errorf("server control id set: %w", err)
	}

	reconnConfig.Bytes = resp.ReconnectToken
	if err := s.config.Put(configControlReconnect, reconnConfig); err != nil {
		return fmt.Errorf("server reconnect set: %w", err)
	}

	if len(resp.ControlAuthenticationKey) != 32 {
		return fmt.Errorf("invalid control auth key length")
	}

	controlPk := [32]byte(resp.ControlAuthenticationKey)
	sharedKey := new([32]byte)
	box.Precompute(sharedKey, &controlPk, relaySk)
	s.authUnsealKey.Store(sharedKey)

	return nil
}

func (s *controlClient) reconnect(ctx context.Context, tfn TransportsFn) (*quic.Conn, error) {
	d := reliable.MinBackoff
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		s.logger.Debug("backoff wait", "d", d)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}

		if conn, err := s.connect(ctx, tfn); err != nil {
			s.logger.Debug("reconnect failed, retrying", "err", err)
		} else {
			return conn, nil
		}

		d = reliable.NextBackoff(d)
		t.Reset(d)
	}
}

func (s *controlClient) runConnection(ctx context.Context, conn *quic.Conn) error {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(s.logger, "error closing connection", "err", err)
		}
	}()

	s.connStatus.Store(statusc.Connected)
	defer s.connStatus.Store(statusc.Reconnecting)

	return quicc.WaitLogRTTStats(ctx, conn, s.logger) // TODO v0.14.0 exchange auth
}

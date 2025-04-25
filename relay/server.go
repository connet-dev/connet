package relay

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/statusc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Ingress  []model.IngressConfig
	Hostport model.HostPort

	Stores Stores

	ControlAddr  *net.UDPAddr
	ControlHost  string
	ControlToken string
	ControlCAs   *x509.CertPool

	Logger *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	configStore, err := cfg.Stores.Config()
	if err != nil {
		return nil, fmt.Errorf("relay stores: %w", err)
	}

	statelessResetVal, err := configStore.GetOrInit(configStatelessReset, func(ck ConfigKey) (ConfigValue, error) {
		var key quic.StatelessResetKey
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return ConfigValue{}, fmt.Errorf("generate rand: %w", err)
		}
		return ConfigValue{Bytes: key[:]}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("relay stateless reset key: %w", err)
	}
	var statelessResetKey quic.StatelessResetKey
	copy(statelessResetKey[:], statelessResetVal.Bytes)

	control, err := newControlClient(cfg, configStore)
	if err != nil {
		return nil, fmt.Errorf("relay control client: %w", err)
	}

	clients := newClientsServer(cfg, control.tlsAuthenticate, control.authenticate)

	return &Server{
		ingress:           cfg.Ingress,
		statelessResetKey: &statelessResetKey,

		control: control,
		clients: clients,

		logger: cfg.Logger.With("relay", cfg.Hostport),
	}, nil
}

type Server struct {
	ingress           []model.IngressConfig
	statelessResetKey *quic.StatelessResetKey

	control *controlClient
	clients *clientsServer

	logger *slog.Logger
}

func (s *Server) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	for i, cfg := range s.ingress {
		s.logger.Debug("start udp listener")
		udpConn, err := net.ListenUDP("udp", cfg.Addr)
		if err != nil {
			return fmt.Errorf("relay server listen: %w", err)
		}
		defer udpConn.Close()

		s.logger.Debug("start quic listener")
		transport := quicc.ServerTransport(udpConn, s.statelessResetKey)
		defer transport.Close()

		// TODO add ip restrictions

		if i == 0 {
			g.Go(func() error { return s.control.run(ctx, transport) }) // TODO maybe accept transports and try to connect on each?
		}
		g.Go(func() error { return s.clients.run(ctx, transport) })
	}

	return g.Wait()
}

func (s *Server) Status(ctx context.Context) (Status, error) {
	stat := s.control.connStatus.Load().(statusc.Status)

	controlID, err := s.getControlID()
	if err != nil {
		return Status{}, err
	}

	fwds := s.getForwards()

	return Status{
		Status:            stat,
		Hostport:          s.control.hostport.String(),
		ControlServerAddr: s.control.controlAddr.String(),
		ControlServerID:   controlID,
		Forwards:          fwds,
	}, nil
}

func (s *Server) getControlID() (string, error) {
	controlIDConfig, err := s.control.config.GetOrDefault(configControlID, ConfigValue{})
	if err != nil {
		return "", err
	}
	return controlIDConfig.String, nil
}

func (s *Server) getForwards() []model.Forward {
	s.clients.forwardMu.RLock()
	defer s.clients.forwardMu.RUnlock()

	return slices.Collect(maps.Keys(s.clients.forwards))
}

type Status struct {
	Status            statusc.Status  `json:"status"`
	Hostport          string          `json:"hostport"`
	ControlServerAddr string          `json:"control_server_addr"`
	ControlServerID   string          `json:"control_server_id"`
	Forwards          []model.Forward `json:"forwards"`
}

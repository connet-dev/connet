package relay

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/statusc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr     *net.UDPAddr
	Hostport model.HostPort

	Stores Stores

	ControlAddr  *net.UDPAddr
	ControlHost  string
	ControlToken string
	ControlCAs   *x509.CertPool

	StatusAddr *net.TCPAddr
	Logger     *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	config, err := cfg.Stores.Config()
	if err != nil {
		return nil, err
	}
	statelessResetVal, err := config.GetOrInit(configStatelessReset, func(ck ConfigKey) (ConfigValue, error) {
		var key quic.StatelessResetKey
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return ConfigValue{}, kleverr.Newf("could not read rand: %w", err)
		}
		return ConfigValue{Bytes: key[:]}, nil
	})
	if err != nil {
		return nil, err
	}
	var statelessResetKey quic.StatelessResetKey
	copy(statelessResetKey[:], statelessResetVal.Bytes)

	control, err := newControlClient(cfg)
	if err != nil {
		return nil, err
	}

	clients := newClientsServer(cfg, control.tlsAuthenticate, control.authenticate)

	return &Server{
		addr:              cfg.Addr,
		statelessResetKey: &statelessResetKey,

		control: control,
		clients: clients,

		statusAddr: cfg.StatusAddr,
		logger:     cfg.Logger.With("relay", cfg.Hostport),
	}, nil
}

type Server struct {
	addr              *net.UDPAddr
	statelessResetKey *quic.StatelessResetKey

	control *controlClient
	clients *clientsServer

	statusAddr *net.TCPAddr
	logger     *slog.Logger
}

func (s *Server) Run(ctx context.Context) error {
	s.logger.Debug("start udp listener")
	udpConn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer udpConn.Close()

	s.logger.Debug("start quic listener")
	transport := &quic.Transport{
		Conn:               udpConn,
		ConnectionIDLength: 8,
		StatelessResetKey:  s.statelessResetKey,
		// TODO review other options
	}
	defer transport.Close()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.control.run(ctx, transport) })
	g.Go(func() error { return s.clients.run(ctx, transport) })
	g.Go(func() error { return s.runStatus(ctx) })

	return g.Wait()
}

func (s *Server) runStatus(ctx context.Context) error {
	if s.statusAddr == nil {
		return nil
	}

	s.logger.Debug("running status server", "addr", s.statusAddr)
	return statusc.Run(ctx, s.statusAddr.String(), s.Status)
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

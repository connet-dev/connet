package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	control, err := newControlClient(cfg)
	if err != nil {
		return nil, err
	}

	clients := newClientsServer(cfg)

	s := &Server{
		addr: cfg.Addr,

		control: control,
		clients: clients,

		statusAddr: cfg.StatusAddr,
		logger:     cfg.Logger.With("relay", cfg.Hostport),
	}

	s.clients.tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		return s.control.clientTLSConfig(chi, s.clients.tlsConf)
	}
	s.clients.auth = s.control.authenticate

	return s, nil
}

type Server struct {
	addr *net.UDPAddr

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
		Conn: udpConn,
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
	return statusc.Run(ctx, s.statusAddr.String(), s.logger, s.Status)
}

func (s *Server) Status() (Status, error) {
	stat := "offline"
	if s.control.connStatus.Load() {
		stat = "online"
	}
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
	Status            string          `json:"status"`
	Hostport          string          `json:"hostport"`
	ControlServerAddr string          `json:"control_server_addr"`
	ControlServerID   string          `json:"control_server_id"`
	Forwards          []model.Forward `json:"forwards"`
}

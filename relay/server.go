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
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/statusc"
	"github.com/quic-go/quic-go"
)

type Config struct {
	ControlAddr  *net.UDPAddr
	ControlHost  string
	ControlToken string
	ControlCAs   *x509.CertPool

	HandshakeIdleTimeout time.Duration

	Ingress []Ingress

	Stores Stores

	Logger *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	if len(cfg.Ingress) == 0 {
		return nil, fmt.Errorf("relay server is missing ingresses")
	}

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

	rootCert, err := certc.NewRoot()
	if err != nil {
		return nil, fmt.Errorf("generate relay cert: %w", err)
	}

	directCert, err := rootCert.NewServer(certc.CertOpts{
		Domains: []string{netc.GenDomainName("reserve.relay")},
	})
	if err != nil {
		return nil, fmt.Errorf("generate direct relay cert: %w", err)
	}

	control, err := newControlClient(cfg, rootCert, directCert, configStore)
	if err != nil {
		return nil, fmt.Errorf("relay control client: %w", err)
	}

	clients, err := newClientsServer(cfg, control.tlsAuthenticate, control.authenticate, rootCert, directCert)
	if err != nil {
		return nil, fmt.Errorf("relay clients server: %w", err)
	}

	return &Server{
		ingress:           cfg.Ingress,
		statelessResetKey: &statelessResetKey,

		control: control,
		clients: clients,
	}, nil
}

type Server struct {
	ingress           []Ingress
	statelessResetKey *quic.StatelessResetKey

	control *controlClient
	clients *clientsServer
}

func (s *Server) Run(ctx context.Context) error {
	transports := notify.NewEmpty[[]*quic.Transport]()
	var waitForTransport TransportsFn = func(ctx context.Context) ([]*quic.Transport, error) {
		t, _, err := transports.GetAny(ctx)
		return t, err
	}

	g := reliable.NewGroup(ctx)

	for _, ingress := range s.ingress {
		cfg := clientsServerCfg{
			ingress:           ingress,
			statelessResetKey: s.statelessResetKey,
			addedTransport: func(t *quic.Transport) {
				notify.SliceAppend(transports, t)
			},
			removeTransport: func(t *quic.Transport) {
				notify.SliceRemove(transports, t)
			},
		}
		g.Go(reliable.Bind(cfg, s.clients.run))
	}

	g.Go(reliable.Bind(waitForTransport, s.control.run))

	return g.Wait()
}

type Status struct {
	Status            statusc.Status   `json:"status"`
	Hostports         []string         `json:"hostports"`
	ControlServerAddr string           `json:"control_server_addr"`
	ControlServerID   string           `json:"control_server_id"`
	Endpoints         []model.Endpoint `json:"endpoints"`
}

func (s *Server) Status(ctx context.Context) (Status, error) {
	stat := s.control.connStatus.Load().(statusc.Status)

	controlID, err := s.getControlID()
	if err != nil {
		return Status{}, err
	}

	eps := s.getEndpoints()

	return Status{
		Status:            stat,
		Hostports:         iterc.MapSliceStrings(s.control.hostports),
		ControlServerAddr: s.control.controlAddr.String(),
		ControlServerID:   controlID,
		Endpoints:         eps,
	}, nil
}

func (s *Server) getControlID() (string, error) {
	controlIDConfig, err := s.control.config.GetOrDefault(configControlID, ConfigValue{})
	if err != nil {
		return "", err
	}
	return controlIDConfig.String, nil
}

func (s *Server) getEndpoints() []model.Endpoint {
	s.clients.controlServer.endpointsMu.RLock()
	defer s.clients.controlServer.endpointsMu.RUnlock()

	return slices.Collect(maps.Keys(s.clients.controlServer.endpoints))
}

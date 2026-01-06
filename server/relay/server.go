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

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/notify"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/statusc"
	"github.com/quic-go/quic-go"
)

type Config struct {
	Metadata string

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
	Status     statusc.Status            `json:"status"`
	Hostports  []string                  `json:"hostports"`
	ServerAddr string                    `json:"server-addrress"`
	ServerID   string                    `json:"server-id"`
	Endpoints  map[string]EndpointStatus `json:"endpoints"`
}

type EndpointStatus struct {
	Endpoint     model.Endpoint `json:"endpoint"`
	Destinations []string       `json:"destinations"`
	Sources      []string       `json:"sources"`
}

func (s *Server) Status(ctx context.Context) (Status, error) {
	stat := s.control.connStatus.Load().(statusc.Status)

	controlID, err := s.getControlID()
	if err != nil {
		return Status{}, err
	}

	eps := s.getEndpoints()

	return Status{
		Status:     stat,
		Hostports:  iterc.MapSliceStrings(s.control.hostports),
		ServerAddr: s.control.controlAddr.String(),
		ServerID:   controlID,
		Endpoints:  eps,
	}, nil
}

func (s *Server) getControlID() (string, error) {
	controlIDConfig, err := s.control.config.GetOrDefault(configControlID, ConfigValue{})
	if err != nil {
		return "", err
	}
	return controlIDConfig.String, nil
}

func (s *Server) getEndpoints() map[string]EndpointStatus {
	s.clients.endpointsMu.RLock()
	defer s.clients.endpointsMu.RUnlock()

	endpoints := map[string]EndpointStatus{}
	for ep, v := range s.clients.endpoints {
		v.mu.RLock()
		destinations := slices.Collect(maps.Keys(v.destinations))
		sources := slices.Collect(maps.Keys(v.sources))
		v.mu.RUnlock()

		endpoints[ep.String()] = EndpointStatus{
			Endpoint:     ep,
			Destinations: iterc.MapSliceStrings(destinations),
			Sources:      iterc.MapSliceStrings(sources),
		}
	}
	return endpoints
}

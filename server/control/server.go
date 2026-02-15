package control

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/logc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/restr"
)

type Config struct {
	ClientsIngress []Ingress
	ClientsAuth    ClientAuthenticator

	RelaysIngress []Ingress
	RelaysAuth    RelayAuthenticator

	Stores Stores

	Logger *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	configStore, err := cfg.Stores.Config()
	if err != nil {
		return nil, fmt.Errorf("config store open: %w", err)
	}

	if err := cfg.Stores.RemoveDeprecated(); err != nil {
		cfg.Logger.Warn("could not remove deprecated stores", "err", err)
	}

	relays, err := newRelayServer(cfg.RelaysIngress, cfg.RelaysAuth, configStore, cfg.Stores, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("create relay server: %w", err)
	}

	clients, err := newClientServer(cfg.ClientsIngress, cfg.ClientsAuth, relays, configStore, cfg.Stores, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("create client server: %w", err)
	}

	return &Server{
		clients: clients,
		relays:  relays,

		config: configStore,
	}, nil
}

type Server struct {
	clients *clientServer
	relays  *relayServer

	config logc.KV[ConfigKey, ConfigValue]
}

func (s *Server) Run(ctx context.Context) error {
	return reliable.RunGroup(ctx,
		s.relays.run,
		s.clients.run,
		logc.ScheduleCompact(s.config),
	)
}

func (s *Server) Status(ctx context.Context) (Status, error) {
	clients, err := s.getClients()
	if err != nil {
		return Status{}, err
	}

	endpoints, err := s.getEndpoints()
	if err != nil {
		return Status{}, err
	}

	relays, err := s.getRelays()
	if err != nil {
		return Status{}, err
	}

	return Status{
		BuildVersion: model.BuildVersion(),

		ClientIngresses: iterc.MapSlice(s.clients.ingresses, StatusIngressFn),
		Clients:         clients,
		Endpoints:       endpoints,

		RelayServerID:  s.relays.id,
		RelayIngresses: iterc.MapSlice(s.relays.ingresses, StatusIngressFn),
		Relays:         relays,
	}, nil
}

func (s *Server) getClients() (map[string]StatusClient, error) {
	clientMsgs, _, err := s.clients.conns.Snapshot()
	if err != nil {
		return nil, err
	}

	clients := map[string]StatusClient{}
	for _, msg := range clientMsgs {
		clients[msg.Key.ID.string] = StatusClient{
			ID:       msg.Key.ID,
			ConnID:   msg.Key.ConnID,
			Address:  msg.Value.Addr,
			Metadata: msg.Value.Metadata,
		}
	}

	return clients, nil
}

func (s *Server) getEndpoints() (map[string]StatusEndpoint, error) {
	peerMsgs, _, err := s.clients.peers.Snapshot()
	if err != nil {
		return nil, err
	}

	endpoints := map[string]StatusEndpoint{}
	for _, msg := range peerMsgs {
		ep := endpoints[msg.Key.Endpoint.String()]
		ep.Endpoint = msg.Key.Endpoint

		switch msg.Key.Role {
		case model.Destination:
			ep.Destinations = append(ep.Destinations, StatusEndpointRemote{msg.Key.ID, msg.Key.ConnID})
		case model.Source:
			ep.Sources = append(ep.Sources, StatusEndpointRemote{msg.Key.ID, msg.Key.ConnID})
		default:
			return nil, fmt.Errorf("unknown role: %s", msg.Key.Role)
		}

		endpoints[msg.Key.Endpoint.String()] = ep
	}

	return endpoints, nil
}

func (s *Server) getRelays() (map[string]StatusRelay, error) {
	msgs, _, err := s.relays.directs.Snapshot()
	if err != nil {
		return nil, err
	}

	relays := map[string]StatusRelay{}
	for _, msg := range msgs {
		relays[msg.Key.ID.string] = StatusRelay{
			ID:        msg.Key.ID,
			Hostports: iterc.MapSlice(msg.Value.Hostports, model.HostPort.String),
			Metadata:  msg.Value.Metadata,
		}
	}

	return relays, nil
}

type Status struct {
	BuildVersion string `json:"build-version"`

	ClientIngresses []StatusIngress           `json:"client-ingresses"`
	Clients         map[string]StatusClient   `json:"clients"`
	Endpoints       map[string]StatusEndpoint `json:"endpoints"`

	RelayServerID  string                 `json:"relay-server-id"`
	RelayIngresses []StatusIngress        `json:"relay-ingresses"`
	Relays         map[string]StatusRelay `json:"relays"`
}

type StatusIngress struct {
	Address      string   `json:"address"`
	Restrictions restr.IP `json:"restrictions"`
}

type StatusClient struct {
	ID       ClientID `json:"id"`
	ConnID   ConnID   `json:"conn_id"`
	Address  string   `json:"address"`
	Metadata string   `json:"metadata"`
}

type StatusEndpoint struct {
	Endpoint     model.Endpoint         `json:"endpoint"`
	Destinations []StatusEndpointRemote `json:"destinations"`
	Sources      []StatusEndpointRemote `json:"sources"`
}

type StatusEndpointRemote struct {
	ID     ClientID `json:"id"`
	ConnID ConnID   `json:"conn_id"`
}

type StatusRelay struct {
	ID        RelayID  `json:"id"`
	Hostports []string `json:"hostport"`
	Metadata  string   `json:"metadata"`
}

func StatusIngressFn(ing Ingress) StatusIngress {
	return StatusIngress{
		Address:      ing.Addr.String(),
		Restrictions: ing.Restr,
	}
}

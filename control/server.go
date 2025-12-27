package control

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/reliable"
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
		Clients:       clients,
		Endpoints:     endpoints,
		RelayServerID: s.relays.id,
		Relays:        relays,
	}, nil
}

func (s *Server) getClients() ([]StatusClient, error) {
	clientMsgs, _, err := s.clients.conns.Snapshot()
	if err != nil {
		return nil, err
	}

	var clients []StatusClient
	for _, msg := range clientMsgs {
		clients = append(clients, StatusClient{
			ID:       msg.Key.ID,
			Addr:     msg.Value.Addr,
			Metadata: msg.Value.Metadata,
		})
	}

	return clients, nil
}

func (s *Server) getEndpoints() ([]StatusEndpoint, error) {
	peerMsgs, _, err := s.clients.peers.Snapshot()
	if err != nil {
		return nil, err
	}

	endpoints := map[model.Endpoint]StatusEndpoint{}
	for _, msg := range peerMsgs {
		ep := endpoints[msg.Key.Endpoint]
		ep.Endpoint = msg.Key.Endpoint

		switch msg.Key.Role {
		case model.Destination:
			ep.Destinations = append(ep.Destinations, msg.Key.ID)
		case model.Source:
			ep.Sources = append(ep.Sources, msg.Key.ID)
		default:
			return nil, fmt.Errorf("unknown role: %s", msg.Key.Role)
		}

		endpoints[msg.Key.Endpoint] = ep
	}

	return slices.Collect(maps.Values(endpoints)), nil
}

func (s *Server) getRelays() ([]StatusRelay, error) {
	msgs, _, err := s.relays.conns.Snapshot()
	if err != nil {
		return nil, err
	}

	var relays []StatusRelay
	for _, msg := range msgs {
		relays = append(relays, StatusRelay{
			ID:        msg.Key.ID,
			Hostports: iterc.MapSlice(msg.Value.Hostports, model.HostPort.String),
			Metadata:  msg.Value.Metadata,
		})
	}

	return relays, nil
}

type Status struct {
	Clients       []StatusClient   `json:"clients"`
	Endpoints     []StatusEndpoint `json:"endpoints"`
	RelayServerID string           `json:"relay_server_id"`
	Relays        []StatusRelay    `json:"relays"`
}

type StatusClient struct {
	ID       ClientID `json:"id"`
	Addr     string   `json:"addr"`
	Metadata string   `json:"metadata"`
}

type StatusEndpoint struct {
	Endpoint     model.Endpoint `json:"endpoint"`
	Destinations []ClientID     `json:"destinations"`
	Sources      []ClientID     `json:"sources"`
}

type StatusRelay struct {
	ID        RelayID  `json:"id"`
	Hostports []string `json:"hostport"`
	Metadata  string   `json:"metadata"`
}

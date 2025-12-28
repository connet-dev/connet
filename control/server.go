package control

import (
	"context"
	"fmt"
	"log/slog"

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

func (s *Server) getClients() (map[string]StatusClient, error) {
	clientMsgs, _, err := s.clients.conns.Snapshot()
	if err != nil {
		return nil, err
	}

	clients := map[string]StatusClient{}
	for _, msg := range clientMsgs {
		clients[msg.Key.ID.string] = StatusClient{
			ID:       msg.Key.ID,
			Addr:     msg.Value.Addr,
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
			ep.Destinations = append(ep.Destinations, msg.Key.ID)
		case model.Source:
			ep.Sources = append(ep.Sources, msg.Key.ID)
		default:
			return nil, fmt.Errorf("unknown role: %s", msg.Key.Role)
		}

		endpoints[msg.Key.Endpoint.String()] = ep
	}

	return endpoints, nil
}

func (s *Server) getRelays() (map[string]StatusRelay, error) {
	msgs, _, err := s.relays.conns.Snapshot()
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
	Clients       map[string]StatusClient   `json:"clients"`
	Endpoints     map[string]StatusEndpoint `json:"endpoints"`
	RelayServerID string                    `json:"relay-server-id"`
	Relays        map[string]StatusRelay    `json:"relays"`
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

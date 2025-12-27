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

	peers, err := s.getPeers()
	if err != nil {
		return Status{}, err
	}

	relays, err := s.getRelays()
	if err != nil {
		return Status{}, err
	}

	return Status{
		ServerID: s.relays.id,
		Clients:  clients,
		Peers:    peers,
		Relays:   relays,
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

func (s *Server) getPeers() ([]StatusPeer, error) {
	peerMsgs, _, err := s.clients.peers.Snapshot()
	if err != nil {
		return nil, err
	}

	var peers []StatusPeer
	for _, msg := range peerMsgs {
		peers = append(peers, StatusPeer{
			ID:       msg.Key.ID,
			Role:     msg.Key.Role,
			Endpoint: msg.Key.Endpoint,
		})
	}

	return peers, nil
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
	ServerID string         `json:"server_id"`
	Clients  []StatusClient `json:"clients"`
	Peers    []StatusPeer   `json:"peers"`
	Relays   []StatusRelay  `json:"relays"`
}

type StatusClient struct {
	ID       ClientID `json:"id"`
	Addr     string   `json:"addr"`
	Metadata string   `json:"metadata"`
}

type StatusPeer struct {
	ID       ClientID       `json:"id"`
	Role     model.Role     `json:"role"`
	Endpoint model.Endpoint `json:"endpoint"`
}

type StatusRelay struct {
	ID        RelayID  `json:"id"`
	Hostports []string `json:"hostport"`
	Metadata  string   `json:"metadata"`
}

package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/restr"
	"github.com/connet-dev/connet/statusc"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Cert tls.Certificate

	ClientsAddr  *net.UDPAddr
	ClientsAuth  ClientAuthenticator
	ClientsRestr restr.IP

	RelaysAddr  *net.UDPAddr
	RelaysAuth  RelayAuthenticator
	RelaysRestr restr.IP

	Stores Stores

	StatusAddr *net.TCPAddr
	Logger     *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	configStore, err := cfg.Stores.Config()
	if err != nil {
		return nil, fmt.Errorf("config store open: %w", err)
	}

	relays, err := newRelayServer(cfg.RelaysAddr, cfg.Cert, cfg.RelaysAuth, cfg.RelaysRestr, configStore, cfg.Stores, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("create relay server: %w", err)
	}

	clients, err := newClientServer(cfg.ClientsAddr, cfg.Cert, cfg.ClientsAuth, cfg.ClientsRestr, relays, configStore, cfg.Stores, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("create client server: %w", err)
	}

	return &Server{
		clients: clients,
		relays:  relays,

		statusAddr: cfg.StatusAddr,
		logger:     cfg.Logger.With("control", cfg.ClientsAddr),
	}, nil
}

type Server struct {
	clients *clientServer
	relays  *relayServer

	statusAddr *net.TCPAddr
	logger     *slog.Logger
}

func (s *Server) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.relays.run(ctx) })
	g.Go(func() error { return s.clients.run(ctx) })
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
			ID:   msg.Key.ID,
			Addr: msg.Value.Addr,
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
			ID:      msg.Key.ID,
			Role:    msg.Key.Role,
			Forward: msg.Key.Forward,
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
			ID:       msg.Key.ID,
			Hostport: msg.Value.Hostport.String(),
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
	ID   ksuid.KSUID `json:"id"`
	Addr string      `json:"addr"`
}

type StatusPeer struct {
	ID      ksuid.KSUID   `json:"id"`
	Role    model.Role    `json:"role"`
	Forward model.Forward `json:"forward"`
}

type StatusRelay struct {
	ID       ksuid.KSUID `json:"id"`
	Hostport string      `json:"hostport"`
}

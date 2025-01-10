package control

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/connet-dev/connet/model"
	"github.com/segmentio/ksuid"
)

type statusServer struct {
	clients *clientServer
	relays  *relayServer
	logger  *slog.Logger
}

func (s *statusServer) run(ctx context.Context) error {
	srv := &http.Server{
		Addr:    ":19180",
		Handler: http.HandlerFunc(s.serve),
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	s.logger.Debug("start http listener", "addr", srv.Addr)
	return srv.ListenAndServe()
}

func (s *statusServer) serve(w http.ResponseWriter, r *http.Request) {
	if err := s.serveErr(w, r); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "server error: %v", err.Error())
	}
}

func (s *statusServer) serveErr(w http.ResponseWriter, _ *http.Request) error {
	clients, err := s.getClients()
	if err != nil {
		return err
	}

	peers, err := s.getPeers()
	if err != nil {
		return err
	}

	relays, err := s.getRelays()
	if err != nil {
		return err
	}

	w.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	return enc.Encode(status{
		ServerID: s.relays.id,
		Clients:  clients,
		Peers:    peers,
		Relays:   relays,
	})
}

func (s *statusServer) getClients() ([]statusClient, error) {
	clientMsgs, _, err := s.clients.conns.Snapshot()
	if err != nil {
		return nil, err
	}

	var clients []statusClient
	for _, msg := range clientMsgs {
		clients = append(clients, statusClient{
			ID:   msg.Key.ID,
			Addr: msg.Value.Addr,
		})
	}

	return clients, nil
}

func (s *statusServer) getPeers() ([]statusPeer, error) {
	peerMsgs, _, err := s.clients.peers.Snapshot()
	if err != nil {
		return nil, err
	}

	var peers []statusPeer
	for _, msg := range peerMsgs {
		peers = append(peers, statusPeer{
			ID:      msg.Key.ID,
			Role:    msg.Key.Role,
			Forward: msg.Key.Forward,
		})
	}

	return peers, nil
}

func (s *statusServer) getRelays() ([]statusRelay, error) {
	msgs, _, err := s.relays.conns.Snapshot()
	if err != nil {
		return nil, err
	}

	var relays []statusRelay
	for _, msg := range msgs {
		relays = append(relays, statusRelay{
			ID:       msg.Key.ID,
			Hostport: msg.Value.Hostport.String(),
		})
	}

	return relays, nil
}

type status struct {
	ServerID string         `json:"server_id"`
	Clients  []statusClient `json:"clients"`
	Peers    []statusPeer   `json:"peers"`
	Relays   []statusRelay  `json:"relays"`
}

type statusClient struct {
	ID   ksuid.KSUID `json:"id"`
	Addr string      `json:"addr"`
}

type statusPeer struct {
	ID      ksuid.KSUID   `json:"id"`
	Role    model.Role    `json:"role"`
	Forward model.Forward `json:"forward"`
}

type statusRelay struct {
	ID       ksuid.KSUID `json:"id"`
	Hostport string      `json:"hostport"`
}

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"

	"github.com/connet-dev/connet/model"
)

type statusServer struct {
	control *controlClient
	clients *clientsServer
	logger  *slog.Logger
}

func (s *statusServer) run(ctx context.Context) error {
	srv := &http.Server{
		Addr:    ":19181",
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
	stat := "disconnected"
	if s.control.connStatus.Load() {
		stat = "online"
	}
	controlID, err := s.getControlID()
	if err != nil {
		return err
	}

	fwds := s.getForwards()

	w.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	return enc.Encode(status{
		Status:            stat,
		Hostport:          s.control.hostport.String(),
		ControlServerAddr: s.control.controlAddr.String(),
		ControlServerID:   controlID,
		Forwards:          fwds,
	})
}

func (s *statusServer) getControlID() (string, error) {
	controlIDConfig, err := s.control.config.GetOrDefault(configControlID, ConfigValue{})
	if err != nil {
		return "", err
	}
	return controlIDConfig.String, nil
}

func (s *statusServer) getForwards() []model.Forward {
	s.clients.forwardMu.RLock()
	defer s.clients.forwardMu.RUnlock()

	return slices.Collect(maps.Keys(s.clients.forwards))
}

type status struct {
	Status            string          `json:"status"`
	Hostport          string          `json:"hostport"`
	ControlServerAddr string          `json:"control_server_addr"`
	ControlServerID   string          `json:"control_server_id"`
	Forwards          []model.Forward `json:"forwards"`
}

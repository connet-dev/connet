package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type statusServer struct {
}

func (s *statusServer) run(ctx context.Context) error {
	srv := &http.Server{
		Addr:    ":19182",
		Handler: http.HandlerFunc(s.serve),
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	return srv.ListenAndServe()
}

func (s *statusServer) serve(w http.ResponseWriter, r *http.Request) {
	if err := s.serveErr(w, r); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "server error: %v", err.Error())
	}
}

func (s *statusServer) serveErr(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	return enc.Encode(status{})
}

type status struct {
}

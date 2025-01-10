package statusc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

func Run[T any](ctx context.Context, addr string, logger *slog.Logger, f func() (T, error)) error {
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stat, err := f()
			if err == nil {
				w.Header().Add("Content-Type", "application/json")
				enc := json.NewEncoder(w)
				err = enc.Encode(stat)
			}
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "server error: %v", err.Error())
			}
		}),
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	logger.Debug("start http listener", "addr", srv.Addr)
	return srv.ListenAndServe()
}

package statusc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/connet-dev/connet/pkg/slogc"
)

func Run[T any](ctx context.Context, addr *net.TCPAddr, f func(ctx context.Context) (T, error)) error {
	srv := &http.Server{
		Addr:              addr.String(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stat, err := f(r.Context())
			if err == nil {
				w.Header().Add("Content-Type", "application/json")
				enc := json.NewEncoder(w)
				err = enc.Encode(stat)
			}
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				if _, err := fmt.Fprintf(w, "server error: %v", err.Error()); err != nil {
					slogc.FineDefault("error writing server error", "err", err)
				}
			}
		}),
	}

	go func() {
		<-ctx.Done()
		if err := srv.Close(); err != nil {
			slogc.FineDefault("error closing status server", "err", err)
		}
	}()

	return srv.ListenAndServe()
}

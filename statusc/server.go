package statusc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// TODO pass the net.Addr in
func Run[T any](ctx context.Context, addr string, f func(ctx context.Context) (T, error)) error {
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stat, err := f(r.Context())
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

	return srv.ListenAndServe()
}

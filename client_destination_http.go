package connet

import (
	"context"
	"net/http"
)

type HTTPDestination struct {
	dst     Destination
	handler http.Handler
}

func NewHTTPDestination(dst Destination, handler http.Handler) (*HTTPDestination, error) {
	return &HTTPDestination{dst, handler}, nil
}

func NewHTTPFileDestination(dst Destination, root string) (*HTTPDestination, error) {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(root)))
	return NewHTTPDestination(dst, mux)
}

func (d *HTTPDestination) Run(ctx context.Context) error {
	srv := &http.Server{
		Handler: d.handler,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	return srv.Serve(d.dst)
}

package netc

import (
	"context"
	"net/http"
)

type FileServer struct {
	Addr string
	Root string
}

func (f *FileServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(f.Root)))

	srv := &http.Server{
		Addr:    f.Addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	return srv.ListenAndServe()
}

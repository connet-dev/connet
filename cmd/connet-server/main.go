package main

import (
	"context"
	"fmt"
	"os"

	"github.com/keihaya-com/connet"
	"github.com/keihaya-com/connet/lib/authc"
)

func main() {
	srv, err := connet.NewServer(
		connet.ServerSelfSigned(),
		connet.ServerAuthenticator(authc.NewStatic("abc")),
		// connet.ServerLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		// 	Level: slog.LevelDebug,
		// }))),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not start server: %v\n", err)
		os.Exit(1)
	}
	if err := srv.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error while running: %v\n", err)
		os.Exit(1)
	}
}

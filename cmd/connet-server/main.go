package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/keihaya-com/connet"
	"github.com/keihaya-com/connet/lib/authc"
)

var debug = flag.Bool("debug", false, "turn on debug logging")

func main() {
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "could not parse flags: %v", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	opts := []connet.ServerOption{
		connet.ServerSelfSigned(),
		connet.ServerAuthenticator(authc.NewStatic("abc")),
	}

	if *debug {
		opts = append(opts,
			connet.ServerLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))),
		)
	}

	srv, err := connet.NewServer(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not start server: %v\n", err)
		os.Exit(1)
	}
	if err := srv.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error while running: %v\n", err)
		os.Exit(1)
	}
}

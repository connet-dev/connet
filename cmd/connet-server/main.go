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
var auth = flag.String("auth", "", "authentication token")
var serverCert = flag.String("server-cert", "", "cert file to use")
var serverKey = flag.String("server-key", "", "key file to use")

func main() {
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "could not parse flags: %v", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *auth == "" {
		fmt.Fprintf(os.Stderr, "auth is required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	opts := []connet.ServerOption{
		connet.ServerAuthenticator(authc.NewStatic(*auth)),
	}

	if *serverCert != "" {
		opts = append(opts, connet.ServerCertificate(*serverCert, *serverKey))
	} else {
		opts = append(opts, connet.ServerSelfSigned())
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

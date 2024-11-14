package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/keihaya-com/connet"
	"github.com/keihaya-com/connet/authc"
)

var auth = flag.String("auth", "", "authentication token")
var listenAddr = flag.String("listen-addr", "", "the address to listen for connections")
var serverCert = flag.String("server-cert", "", "cert file to use")
var serverKey = flag.String("server-key", "", "key file to use")
var debug = flag.Bool("debug", false, "turn on debug logging")

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

	if *listenAddr != "" {
		opts = append(opts, connet.ServerAddress(*listenAddr))
	}

	if *serverCert != "" {
		opts = append(opts, connet.ServerCertificate(*serverCert, *serverKey))
	} else {
		fmt.Fprintf(os.Stderr, "cert is required")
		flag.PrintDefaults()
		os.Exit(1)
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

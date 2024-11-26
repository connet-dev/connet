package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/keihaya-com/connet"
)

var auth = flag.String("auth", "", "authentication token")
var controlAddr = flag.String("control-addr", "", "the address to listen for control connections")
var relayAddr = flag.String("relay-addr", "", "the address to listen for relay connections")
var relayHostport = flag.String("relay-hostport", "", "the public relay hostport to send to clients")
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
		connet.ServerAuthenticator(connet.NewStaticAuthenticator(*auth)),
	}

	if *controlAddr != "" {
		opts = append(opts, connet.ServerControlAddress(*controlAddr))
	}

	if *relayAddr != "" {
		opts = append(opts, connet.ServerRelayAddresses(*relayAddr, *relayHostport))
	}

	if *serverCert != "" {
		opts = append(opts, connet.ServerCertificate(*serverCert, *serverKey))
	} else {
		fmt.Fprintf(os.Stderr, "cert is required, generate one using minica or similar tool")
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

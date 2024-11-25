package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/keihaya-com/connet"
)

var serverAddr = flag.String("server-addr", "", "target server")
var directAddr = flag.String("direct-addr", "", "the address to listen for direct connections")
var auth = flag.String("auth", "", "authentication token")
var destinationName = flag.String("destination-name", "", "name to listen on")
var destinationAddr = flag.String("destination-addr", "", "forward incoming conns to")
var sourceAddr = flag.String("source-addr", "", "listen for incoming conns")
var sourceName = flag.String("source-name", "", "name to connect to")
var caCert = flag.String("ca-cert", "", "ca cert file to use")
var caKey = flag.String("ca-key", "", "ca key file to use")
var debug = flag.Bool("debug", false, "turn on debug logging")

func main() {
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "could not parse flags: %v", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	var opts = []connet.ClientOption{
		connet.ClientAuthentication(*auth),
	}

	if *serverAddr != "" {
		opts = append(opts, connet.ClientServerAddress(*serverAddr))
	}

	if *directAddr != "" {
		opts = append(opts, connet.ClientDirectAddress(*directAddr))
	}

	if *caCert != "" {
		opts = append(opts, connet.ClientCA(*caCert, *caKey))
	}

	if *destinationName != "" {
		opts = append(opts, connet.ClientDestination(*destinationName, *destinationAddr))
	}

	if *sourceName != "" {
		opts = append(opts, connet.ClientSource(*sourceAddr, *sourceName))
	}

	if *debug {
		opts = append(opts,
			connet.ClientLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))),
		)
	}

	c, err := connet.NewClient(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could create client: %v", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := c.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "could create client: %v", err)
	}
}

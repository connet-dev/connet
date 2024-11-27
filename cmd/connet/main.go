package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/keihaya-com/connet"
)

type Config struct {
	LogLevel  string       `toml:"log_level"`
	LogFormat string       `toml:"log_format"`
	Server    ServerConfig `toml:"server"`
	Client    ClientConfig `toml:"client"`
}

type ServerConfig struct {
	Tokens   []string       `toml:"tokens"`
	Hostname string         `toml:"hostname"`
	Control  ListenerConfig `toml:"control"`
	Relay    ListenerConfig `toml:"relay"`
}

type ClientConfig struct {
	Token      string         `toml:"token"`
	ServerAddr string         `toml:"server_addr"`
	ServerCert string         `toml:"server_cert_file"`
	Direct     ListenerConfig `toml:"direct"`

	Destinations map[string]ForwardConfig `toml:"destinations"`
	Sources      map[string]ForwardConfig `toml:"sources"`
}

type ListenerConfig struct {
	Addr string `toml:"bind_addr"`
	Cert string `toml:"cert_file"`
	Key  string `toml:"key_file"`
}

type ForwardConfig struct {
	Addr  string `toml:"addr"`
	Route string `toml:"route"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: connet [server|client|check] <config-file>")
		os.Exit(1)
	}

	var cfg Config
	md, err := toml.DecodeFile(os.Args[2], &cfg)
	if err != nil {
		fmt.Printf("Could not parse '%s' config file: %v\n", os.Args[2], err)
		os.Exit(2)
	}

	logger := logger(cfg)

	switch os.Args[1] {
	case "server":
		if err := server(cfg.Server, logger); err != nil {
			fmt.Printf("Error while running server: %v\n", err)
			os.Exit(4)
		}
		os.Exit(0)
	case "client":
		if err := client(cfg.Client, logger); err != nil {
			fmt.Printf("Error while running client: %v\n", err)
			os.Exit(5)
		}
		os.Exit(0)
	case "check":
		if len(md.Undecoded()) > 0 {
			fmt.Println("Invalid configuration file (unknown keys):", md.Undecoded())
			os.Exit(6)
		}
		fmt.Println("Valid configuration file")
		os.Exit(0)
	default:
		fmt.Println("Unknown command, try one of [server|client|check]")
		os.Exit(3)
	}
}

func logger(cfg Config) *slog.Logger {
	logLevel := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	case "info":
		logLevel = slog.LevelInfo
	}

	switch cfg.LogFormat {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		}))
	case "text":
		fallthrough
	default:
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		}))
	}
}

func server(cfg ServerConfig, logger *slog.Logger) error {
	var opts []connet.ServerOption

	opts = append(opts, connet.ServerTokens(cfg.Tokens...))
	opts = append(opts, connet.ServerHostname(cfg.Hostname))
	opts = append(opts, connet.ServerControl(cfg.Control.Addr, cfg.Control.Cert, cfg.Control.Key))
	opts = append(opts, connet.ServerRelay(cfg.Relay.Addr, cfg.Relay.Cert, cfg.Relay.Key))
	opts = append(opts, connet.ServerLogger(logger))

	srv, err := connet.NewServer(opts...)
	if err != nil {
		return err
	}
	return srv.Run(context.Background())
}

func client(cfg ClientConfig, logger *slog.Logger) error {
	var opts []connet.ClientOption

	opts = append(opts, connet.ClientToken(cfg.Token))
	opts = append(opts, connet.ClientControlServer(cfg.ServerAddr, cfg.ServerCert))
	opts = append(opts, connet.ClientDirectServer(cfg.Direct.Addr, cfg.Direct.Cert, cfg.Direct.Key))
	opts = append(opts, connet.ClientLogger(logger))

	for name, fc := range cfg.Destinations {
		opts = append(opts, connet.ClientDestination(name, fc.Addr))
	}
	for name, fc := range cfg.Sources {
		opts = append(opts, connet.ClientSource(name, fc.Addr))
	}

	cl, err := connet.NewClient(opts...)
	if err != nil {
		return err
	}
	return cl.Run(context.Background())
}

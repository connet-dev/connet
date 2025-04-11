package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/relay"
	"github.com/spf13/cobra"
)

type RelayConfig struct {
	Token     string `toml:"token"`
	TokenFile string `toml:"token-file"`

	Addr     string `toml:"addr"`
	Hostname string `toml:"hostname"`

	ControlAddr string `toml:"control-addr"`
	ControlCAs  string `toml:"control-cas"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

func relayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "run connet relay server",
	}

	filenames := cmd.Flags().StringArray("config", nil, "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.Token, "token", "", "token to use")
	cmd.Flags().StringVar(&flagsConfig.Relay.TokenFile, "token-file", "", "token file to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.Addr, "addr", "", "server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Relay.Hostname, "hostname", "", "server public hostname to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.ControlAddr, "control-addr", "", "control server address to connect")
	cmd.Flags().StringVar(&flagsConfig.Relay.ControlCAs, "control-cas", "", "control server CAs to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Relay.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet relay server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		cfg.merge(flagsConfig)

		logger, err := logger(cfg)
		if err != nil {
			return fmt.Errorf("configure logger: %w", err)
		}

		return relayRun(cmd.Context(), cfg.Relay, logger)
	})

	return cmd
}

func relayRun(ctx context.Context, cfg RelayConfig, logger *slog.Logger) error {
	relayCfg := relay.Config{
		Logger: logger,
	}

	if cfg.TokenFile != "" {
		tokens, err := loadTokens(cfg.TokenFile)
		if err != nil {
			return err
		}
		relayCfg.ControlToken = tokens[0]
	} else {
		relayCfg.ControlToken = cfg.Token
	}

	if cfg.Addr == "" {
		cfg.Addr = ":19191"
		if cfg.Hostname == "" {
			cfg.Hostname = "localhost"
		}
	}
	serverAddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("resolve server address: %w", err)
	}
	relayCfg.Addr = serverAddr

	relayCfg.Hostport = model.HostPort{Host: cfg.Hostname, Port: uint16(serverAddr.Port)}

	if cfg.ControlAddr == "" {
		cfg.ControlAddr = "localhost:19189"
	}
	controlAddr, err := net.ResolveUDPAddr("udp", cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("resolve control address: %w", err)
	}
	relayCfg.ControlAddr = controlAddr

	if cfg.ControlCAs != "" {
		casData, err := os.ReadFile(cfg.ControlCAs)
		if err != nil {
			return fmt.Errorf("read server CAs: %w", err)
		}

		cas := x509.NewCertPool()
		if !cas.AppendCertsFromPEM(casData) {
			return fmt.Errorf("missing server CA certificate in %s", cfg.ControlCAs)
		}
		relayCfg.ControlCAs = cas
	}

	controlHost, _, err := net.SplitHostPort(cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("split control address: %w", err)
	}
	relayCfg.ControlHost = controlHost

	if cfg.StatusAddr != "" {
		statusAddr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("resolve status address: %w", err)
		}
		relayCfg.StatusAddr = statusAddr
	}

	if cfg.StoreDir == "" {
		dir, err := os.MkdirTemp("", "connet-relay-")
		if err != nil {
			return fmt.Errorf("create /tmp dir: %w", err)
		}
		logger.Info("using temporary store directory", "dir", dir)
		cfg.StoreDir = dir
	}
	relayCfg.Stores = relay.NewFileStores(cfg.StoreDir)

	srv, err := relay.NewServer(relayCfg)
	if err != nil {
		return fmt.Errorf("create relay server: %w", err)
	}
	return srv.Run(ctx)
}

func (c *RelayConfig) merge(o RelayConfig) {
	if o.Token != "" && o.TokenFile != "" { // new config completely overrides token
		c.Token = o.Token
		c.TokenFile = o.TokenFile
	}

	c.Addr = override(c.Addr, o.Addr)
	c.Hostname = override(c.Hostname, o.Hostname)

	c.ControlAddr = override(c.ControlAddr, o.ControlAddr)
	c.ControlCAs = override(c.ControlCAs, o.ControlCAs)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

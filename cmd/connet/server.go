package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet"
	"github.com/spf13/cobra"
)

type ServerConfig struct {
	Ingresses []ControlIngress `toml:"ingress"`

	Tokens            []string           `toml:"tokens"`
	TokensFile        string             `toml:"tokens-file"`
	TokenRestrictions []TokenRestriction `toml:"token-restriction"`

	RelayAddr     string `toml:"relay-addr"`
	RelayHostname string `toml:"relay-hostname"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "run connet server",
	}
	cmd.Flags().SortFlags = false

	filenames := cmd.Flags().StringArray("config", nil, "config file to load, can be passed mulitple times")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	var ingress ControlIngress
	cmd.Flags().StringVar(&ingress.Addr, "addr", "", "control server addr to use")
	cmd.Flags().StringVar(&ingress.Cert, "cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&ingress.Key, "key-file", "", "control server key to use")
	cmd.Flags().StringArrayVar(&ingress.IPRestriction.AllowCIDRs, "allow-cidr", nil, "cidr to allow client connections from")
	cmd.Flags().StringArrayVar(&ingress.IPRestriction.DenyCIDRs, "deny-cidr", nil, "cidr to deny client connections from")

	cmd.Flags().StringArrayVar(&flagsConfig.Server.Tokens, "tokens", nil, "tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Server.TokensFile, "tokens-file", "", "tokens file to load")

	cmd.Flags().StringVar(&flagsConfig.Server.RelayAddr, "relay-addr", "", "relay server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.RelayHostname, "relay-hostname", "", "relay server public hostname to use")

	cmd.Flags().StringVar(&flagsConfig.Server.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Server.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if !ingress.isZero() {
			flagsConfig.Server.Ingresses = append(flagsConfig.Server.Ingresses, ingress)
		}
		cfg.merge(flagsConfig)

		logger, err := logger(cfg)
		if err != nil {
			return fmt.Errorf("configure logger: %w", err)
		}

		return serverRun(cmd.Context(), cfg.Server, logger)
	})

	return cmd
}

func serverRun(ctx context.Context, cfg ServerConfig, logger *slog.Logger) error {
	var opts []connet.ServerOption

	var usedDefault bool
	for ix, ingressCfg := range cfg.Ingresses {
		if ingressCfg.Addr == "" && !usedDefault {
			ingressCfg.Addr = ":19190"
			usedDefault = true
		}
		if ingress, err := ingressCfg.parse(); err != nil {
			return fmt.Errorf("parse ingress at %d: %w", ix, err)
		} else {
			opts = append(opts, connet.ServerClientsIngress(ingress))
		}
	}

	var err error
	tokens := cfg.Tokens
	if cfg.TokensFile != "" {
		tokens, err = loadTokens(cfg.TokensFile)
		if err != nil {
			return err
		}
	}
	clientAuth, err := parseClientAuth(tokens, cfg.TokenRestrictions)
	if err != nil {
		return err
	}
	opts = append(opts, connet.ServerClientsAuthenticator(clientAuth))

	if cfg.RelayAddr != "" {
		opts = append(opts, connet.ServerRelayAddress(cfg.RelayAddr))
	}
	if cfg.RelayHostname != "" {
		opts = append(opts, connet.ServerRelayHostname(cfg.RelayHostname))
	}

	var statusAddr *net.TCPAddr
	if cfg.StatusAddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("resolve status address: %w", err)
		}
		statusAddr = addr
	}

	if cfg.StoreDir != "" {
		opts = append(opts, connet.ServerStoreDir(cfg.StoreDir))
	}

	opts = append(opts, connet.ServerLogger(logger))

	srv, err := connet.NewServer(opts...)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	return runWithStatus(ctx, srv, statusAddr, logger)
}

func (c *ServerConfig) merge(o ServerConfig) {
	c.Ingresses = mergeSlices(c.Ingresses, o.Ingresses)
	if len(o.Tokens) > 0 || o.TokensFile != "" { // new config completely overrides tokens
		c.Tokens = o.Tokens
		c.TokensFile = o.TokensFile
	}
	c.TokenRestrictions = mergeSlices(c.TokenRestrictions, o.TokenRestrictions)

	c.RelayAddr = override(c.RelayAddr, o.RelayAddr)
	c.RelayHostname = override(c.RelayHostname, o.RelayHostname)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

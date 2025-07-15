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

	RelayIngresses []RelayIngress `toml:"relay-ingress"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "run connet server",
	}
	cmd.Flags().SortFlags = false

	filenames := cmd.Flags().StringArray("config", nil, "config file to load, can be passed multiple times")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	var clientIngress ControlIngress
	cmd.Flags().StringVar(&clientIngress.Addr, "addr", "", "control server addr to use")
	cmd.Flags().StringVar(&clientIngress.Cert, "cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&clientIngress.Key, "key-file", "", "control server key to use")
	cmd.Flags().StringArrayVar(&clientIngress.AllowCIDRs, "allow-cidr", nil, "cidr to allow client connections from")
	cmd.Flags().StringArrayVar(&clientIngress.DenyCIDRs, "deny-cidr", nil, "cidr to deny client connections from")

	cmd.Flags().StringArrayVar(&flagsConfig.Server.Tokens, "tokens", nil, "tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Server.TokensFile, "tokens-file", "", "tokens file to load")

	var relayIngress RelayIngress
	cmd.Flags().StringVar(&relayIngress.Addr, "relay-addr", "", "relay server addr to use")
	cmd.Flags().StringArrayVar(&relayIngress.Hostports, "relay-hostport", nil, "relay server public host[:port] to use (if port is missing will use addr's port)")
	cmd.Flags().StringArrayVar(&relayIngress.AllowCIDRs, "relay-allow-cidr", nil, "cidr to allow client relay connections from")
	cmd.Flags().StringArrayVar(&relayIngress.DenyCIDRs, "relay-deny-cidr", nil, "cidr to deny client relay connections from")

	cmd.Flags().StringVar(&flagsConfig.Server.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Server.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if !clientIngress.isZero() {
			flagsConfig.Server.Ingresses = append(flagsConfig.Server.Ingresses, clientIngress)
		}
		if !relayIngress.isZero() {
			flagsConfig.Server.RelayIngresses = append(flagsConfig.Server.RelayIngresses, relayIngress)
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

	var usedClientDefault bool
	for ix, ingressCfg := range cfg.Ingresses {
		if ingressCfg.Addr == "" && !usedClientDefault {
			ingressCfg.Addr = ":19190"
			usedClientDefault = true
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

	var usedRelayDefault bool
	for ix, ingressCfg := range cfg.RelayIngresses {
		if ingressCfg.Addr == "" && !usedRelayDefault {
			ingressCfg.Addr = ":19191"
			usedRelayDefault = true
		}
		if ingress, err := ingressCfg.parse(); err != nil {
			return fmt.Errorf("parse ingress at %d: %w", ix, err)
		} else {
			opts = append(opts, connet.ServerRelayIngress(ingress))
		}
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

	c.RelayIngresses = mergeSlices(c.RelayIngresses, o.RelayIngresses)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

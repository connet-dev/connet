package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet"
	"github.com/connet-dev/connet/statusc"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type ServerConfig struct {
	Cert string `toml:"cert-file"`
	Key  string `toml:"key-file"`

	Addr              string             `toml:"addr"`
	IPRestriction     IPRestriction      `toml:"ip-restriction"`
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

	filenames := cmd.Flags().StringArray("config", nil, "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Server.Addr, "addr", "", "control server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Cert, "cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Key, "key-file", "", "control server key to use")

	cmd.Flags().StringArrayVar(&flagsConfig.Server.Tokens, "tokens", nil, "tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Server.TokensFile, "tokens-file", "", "tokens file to load")
	cmd.Flags().StringSliceVar(&flagsConfig.Server.IPRestriction.AllowCIDRs, "tokens-allow-cidr", nil, "cidr to allow client connections from")
	cmd.Flags().StringSliceVar(&flagsConfig.Server.IPRestriction.DenyCIDRs, "tokens-deny-cidr", nil, "cidr to deny client connections from")

	cmd.Flags().StringVar(&flagsConfig.Server.RelayAddr, "relay-addr", "", "relay server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.RelayHostname, "relay-hostname", "", "relay server public hostname to use")

	cmd.Flags().StringVar(&flagsConfig.Server.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Server.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
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

	if cfg.Addr != "" {
		opts = append(opts, connet.ServerClientsAddress(cfg.Addr))
	}
	if cfg.Cert != "" {
		opts = append(opts, connet.ServerCertificate(cfg.Cert, cfg.Key))
	}

	if len(cfg.IPRestriction.AllowCIDRs) > 0 || len(cfg.IPRestriction.DenyCIDRs) > 0 {
		opts = append(opts, connet.ServerClientRestrictions(cfg.IPRestriction.AllowCIDRs, cfg.IPRestriction.DenyCIDRs))
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
	opts = append(opts, connet.ServerClientAuthenticator(clientAuth))

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

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return srv.Run(ctx) })

	if statusAddr != nil {
		g.Go(func() error {
			logger.Debug("running status server", "addr", statusAddr)
			return statusc.Run(ctx, statusAddr.String(), srv.Status)
		})
	}

	return g.Wait()
}

func (c *ServerConfig) merge(o ServerConfig) {
	c.Cert = override(c.Cert, o.Cert)
	c.Key = override(c.Key, o.Key)

	c.Addr = override(c.Addr, o.Addr)
	c.IPRestriction.AllowCIDRs = overrides(c.IPRestriction.AllowCIDRs, o.IPRestriction.AllowCIDRs)
	c.IPRestriction.DenyCIDRs = overrides(c.IPRestriction.DenyCIDRs, o.IPRestriction.DenyCIDRs)
	if len(o.Tokens) > 0 || o.TokensFile != "" { // new config completely overrides tokens
		c.Tokens = o.Tokens
		c.TokensFile = o.TokensFile
	}
	if len(c.TokenRestrictions) == len(o.TokenRestrictions) {
		for i := range c.TokenRestrictions {
			c.TokenRestrictions[i] = mergeTokenRestriction(c.TokenRestrictions[i], o.TokenRestrictions[i])
		}
	} else if len(o.TokenRestrictions) > 0 {
		c.TokenRestrictions = o.TokenRestrictions
	}

	c.RelayAddr = override(c.RelayAddr, o.RelayAddr)
	c.RelayHostname = override(c.RelayHostname, o.RelayHostname)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet/server"
	"github.com/spf13/cobra"
)

type ServerConfig struct {
	Ingresses []ControlIngress `toml:"ingress"`

	TokensFile        string             `toml:"tokens-file"`
	Tokens            []string           `toml:"tokens"`
	TokenRestrictions []TokenRestriction `toml:"token-restriction"`

	EndpointExpiryDisable bool          `toml:"endpoint-expiry-disable"`
	EndpointExpiryTimeout durationValue `toml:"endpoint-expiry-timeout"`

	RelayIngresses []RelayIngress `toml:"relay-ingress"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run a connet server (control and relay server as one)",
	}
	cmd.Flags().SortFlags = false

	filenames := addConfigsFlag(cmd)

	var flagsConfig Config
	flagsConfig.addLogFlags(cmd)

	cmd.Flags().StringVar(&flagsConfig.Server.TokensFile, "tokens-file", "", "file containing list of client auth tokens (token per line)")
	cmd.Flags().StringArrayVar(&flagsConfig.Server.Tokens, "tokens", nil, "list of client auth tokens (fallback 'tokens-file' is not specified)")

	var clientIngress ControlIngress
	cmd.Flags().StringVar(&clientIngress.Addr, "addr", "", "clients server address to listen for connection (UDP/QUIC, [host]:port) (defaults to ':19190')")
	cmd.Flags().StringVar(&clientIngress.Cert, "cert-file", "", "clients server TLS certificate file (pem format)")
	cmd.Flags().StringVar(&clientIngress.Key, "key-file", "", "clients server TLS certificate private key file (pem format)")
	cmd.Flags().StringArrayVar(&clientIngress.AllowCIDRs, "allow-cidr", nil, "list of allowed networks for client connections (CIDR format)")
	cmd.Flags().StringArrayVar(&clientIngress.DenyCIDRs, "deny-cidr", nil, "list of denied networks for client connections (CIDR format)")

	cmd.Flags().BoolVar(&flagsConfig.Server.EndpointExpiryDisable, "endpoint-expiry-disable", false, "disable keeping endpoint registrations alive after client disconnect (default false)")
	cmd.Flags().Var(&flagsConfig.Server.EndpointExpiryTimeout, "endpoint-expiry-timeout", "how long to keep endpoint registrations after client disconnect (default '30s')")

	var relayIngress RelayIngress
	cmd.Flags().StringVar(&relayIngress.Addr, "relay-addr", "", "relay clients server address (UDP/QUIC, [host]:port) (defaults to ':19191')")
	cmd.Flags().StringArrayVar(&relayIngress.Hostports, "relay-hostport", nil, `list of host[:port]s advertised by the control server for clients to connect to this relay
  defaults to 'localhost:<port in addr>', if port is not set will use the addr's port`)
	cmd.Flags().StringArrayVar(&relayIngress.AllowCIDRs, "relay-allow-cidr", nil, "list of allowed networks for relay client connections (CIDR format)")
	cmd.Flags().StringArrayVar(&relayIngress.DenyCIDRs, "relay-deny-cidr", nil, "list of denied networks for relay client connections (CIDR format)")

	addStatusAddrFlag(cmd, &flagsConfig.Server.StatusAddr)
	addStoreDirFlag(cmd, &flagsConfig.Server.StoreDir)

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

func addStoreDirFlag(cmd *cobra.Command, ref *string) {
	cmd.Flags().StringVar(ref, "store-dir", "", `directory to store persistent state
  when empty will try the following environment variables: CONNET_STATE_DIR, STATE_DIRECTORY
  if still empty, it will try to create a subdirectory in the current system TMPDIR directory`)
}

func serverRun(ctx context.Context, cfg ServerConfig, logger *slog.Logger) error {
	var opts []server.Option

	var usedClientDefault bool
	for ix, ingressCfg := range cfg.Ingresses {
		if ingressCfg.Addr == "" && !usedClientDefault {
			ingressCfg.Addr = ":19190"
			usedClientDefault = true
		}
		if ingress, err := ingressCfg.parse(); err != nil {
			return fmt.Errorf("parse ingress at %d: %w", ix, err)
		} else {
			opts = append(opts, server.ClientsIngress(ingress))
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
	opts = append(opts, server.ClientsAuthenticator(clientAuth))

	endpointExpiry := resolveEndpointExpiry(cfg.EndpointExpiryDisable, cfg.EndpointExpiryTimeout)
	opts = append(opts, server.ClientsEndpointExpiry(endpointExpiry))

	var usedRelayDefault bool
	for ix, ingressCfg := range cfg.RelayIngresses {
		if ingressCfg.Addr == "" && !usedRelayDefault {
			ingressCfg.Addr = ":19191"
			usedRelayDefault = true
		}
		if ingress, err := ingressCfg.parse(); err != nil {
			return fmt.Errorf("parse ingress at %d: %w", ix, err)
		} else {
			opts = append(opts, server.RelayIngress(ingress))
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
		opts = append(opts, server.StoreDir(cfg.StoreDir))
	}

	opts = append(opts, server.Logger(logger))

	srv, err := server.New(opts...)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	err = runWithStatus(ctx, srv, statusAddr, logger)
	logger.Info("server stopped, draining conns")
	srv.WaitDrainConns(ctx)
	logger.Info("server stopped, completed conns")
	return err
}

func (c *ServerConfig) merge(o ServerConfig) {
	c.Ingresses = mergeSlices(c.Ingresses, o.Ingresses)
	if len(o.Tokens) > 0 || o.TokensFile != "" { // new config completely overrides tokens
		c.Tokens = o.Tokens
		c.TokensFile = o.TokensFile
	}
	c.TokenRestrictions = mergeSlices(c.TokenRestrictions, o.TokenRestrictions)

	c.EndpointExpiryDisable = c.EndpointExpiryDisable || o.EndpointExpiryDisable
	c.EndpointExpiryTimeout = override(c.EndpointExpiryTimeout, o.EndpointExpiryTimeout)

	c.RelayIngresses = mergeSlices(c.RelayIngresses, o.RelayIngresses)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

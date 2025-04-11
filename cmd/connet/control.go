package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/restr"
	"github.com/connet-dev/connet/selfhosted"
	"github.com/spf13/cobra"
)

type ControlConfig struct {
	Cert string `toml:"cert-file"`
	Key  string `toml:"key-file"`

	ClientsAddr              string             `toml:"clients-addr"`
	ClientsIPRestriction     IPRestriction      `toml:"clients-ip-restriction"`
	ClientsTokens            []string           `toml:"clients-tokens"`
	ClientsTokensFile        string             `toml:"clients-tokens-file"`
	ClientsTokenRestrictions []TokenRestriction `toml:"clients-token-restriction"`

	RelaysAddr                string          `toml:"relays-addr"`
	RelaysIPRestriction       IPRestriction   `toml:"relays-ip-restriction"`
	RelaysTokens              []string        `toml:"relays-tokens"`
	RelaysTokensFile          string          `toml:"relays-tokens-file"`
	RelaysTokenIPRestrictions []IPRestriction `toml:"relays-token-ip-restriction"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

type IPRestriction struct {
	AllowCIDRs []string `toml:"allow-cidrs"`
	DenyCIDRs  []string `toml:"deny-cidrs"`
}

type TokenRestriction struct {
	AllowCIDRs  []string `toml:"allow-cidrs"`
	DenyCIDRs   []string `toml:"deny-cidrs"`
	NameMatches string   `toml:"name-matches"`
	RoleMatches string   `toml:"role-matches"`
}

func controlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control",
		Short: "run connet control server",
	}

	filenames := cmd.Flags().StringArray("config", nil, "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Control.Cert, "cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Control.Key, "key-file", "", "control server key to use")

	cmd.Flags().StringVar(&flagsConfig.Control.ClientsAddr, "clients-addr", "", "control client server addr to use")
	cmd.Flags().StringArrayVar(&flagsConfig.Control.ClientsTokens, "clients-tokens", nil, "client tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Control.ClientsTokensFile, "clients-tokens-file", "", "client tokens file to load")
	cmd.Flags().StringSliceVar(&flagsConfig.Control.ClientsIPRestriction.AllowCIDRs, "clients-allow-cidr", nil, "cidr to allow client connections from")
	cmd.Flags().StringSliceVar(&flagsConfig.Control.ClientsIPRestriction.DenyCIDRs, "clients-deny-cidr", nil, "cidr to deny client connections from")

	cmd.Flags().StringVar(&flagsConfig.Control.RelaysAddr, "relays-addr", "", "control relay server addr to use")
	cmd.Flags().StringArrayVar(&flagsConfig.Control.RelaysTokens, "relays-tokens", nil, "relay tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Control.RelaysTokensFile, "relays-tokens-file", "", "relay tokens file to load")
	cmd.Flags().StringSliceVar(&flagsConfig.Control.RelaysIPRestriction.AllowCIDRs, "relays-allow-cidr", nil, "cidr to allow relay connections from")
	cmd.Flags().StringSliceVar(&flagsConfig.Control.RelaysIPRestriction.DenyCIDRs, "relays-deny-cidr", nil, "cidr to deny relay connections from")

	cmd.Flags().StringVar(&flagsConfig.Control.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Control.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet control server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		cfg.merge(flagsConfig)

		logger, err := logger(cfg)
		if err != nil {
			return fmt.Errorf("configure logger: %w", err)
		}

		return controlRun(cmd.Context(), cfg.Control, logger)
	})

	return cmd
}

func controlRun(ctx context.Context, cfg ControlConfig, logger *slog.Logger) error {
	controlCfg := control.Config{
		Logger: logger,
	}

	if cfg.Cert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return fmt.Errorf("load server certificate: %w", err)
		}
		controlCfg.Cert = cert
	}

	if cfg.ClientsAddr == "" {
		cfg.ClientsAddr = ":19190"
	}
	clientAddr, err := net.ResolveUDPAddr("udp", cfg.ClientsAddr)
	if err != nil {
		return fmt.Errorf("resolve clients address: %w", err)
	}
	controlCfg.ClientsAddr = clientAddr

	if len(cfg.ClientsIPRestriction.AllowCIDRs) > 0 || len(cfg.ClientsIPRestriction.DenyCIDRs) > 0 {
		iprestr, err := restr.ParseIP(cfg.ClientsIPRestriction.AllowCIDRs, cfg.ClientsIPRestriction.DenyCIDRs)
		if err != nil {
			return fmt.Errorf("parse client restrictions: %w", err)
		}
		controlCfg.ClientsRestr = iprestr
	}

	clientTokens := cfg.ClientsTokens
	if cfg.ClientsTokensFile != "" {
		clientTokens, err = loadTokens(cfg.ClientsTokensFile)
		if err != nil {
			return fmt.Errorf("load clients tokens: %w", err)
		}
	}
	controlCfg.ClientsAuth, err = parseClientAuth(clientTokens, cfg.ClientsTokenRestrictions)
	if err != nil {
		return err
	}

	if cfg.RelaysAddr == "" {
		cfg.RelaysAddr = ":19189"
	}
	relayAddr, err := net.ResolveUDPAddr("udp", cfg.RelaysAddr)
	if err != nil {
		return fmt.Errorf("resolve relays address: %w", err)
	}
	controlCfg.RelaysAddr = relayAddr

	if len(cfg.RelaysIPRestriction.AllowCIDRs) > 0 || len(cfg.RelaysIPRestriction.DenyCIDRs) > 0 {
		iprestr, err := restr.ParseIP(cfg.RelaysIPRestriction.AllowCIDRs, cfg.RelaysIPRestriction.DenyCIDRs)
		if err != nil {
			return fmt.Errorf("parse relays ip restriction: %w", err)
		}
		controlCfg.RelaysRestr = iprestr
	}

	relayTokens := cfg.RelaysTokens
	if cfg.RelaysTokensFile != "" {
		relayTokens, err = loadTokens(cfg.RelaysTokensFile)
		if err != nil {
			return fmt.Errorf("load relays tokens: %w", err)
		}
	}
	controlCfg.RelaysAuth, err = parseRelayAuth(relayTokens, cfg.RelaysTokenIPRestrictions)
	if err != nil {
		return err
	}

	if cfg.StatusAddr != "" {
		statusAddr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("resolve status address: %w", err)
		}
		controlCfg.StatusAddr = statusAddr
	}

	if cfg.StoreDir == "" {
		dir, err := os.MkdirTemp("", "connet-control-")
		if err != nil {
			return fmt.Errorf("create /tmp dir: %w", err)
		}
		logger.Info("using temporary store directory", "dir", dir)
		cfg.StoreDir = dir
	}
	controlCfg.Stores = control.NewFileStores(cfg.StoreDir)

	srv, err := control.NewServer(controlCfg)
	if err != nil {
		return fmt.Errorf("create control server: %w", err)
	}
	return srv.Run(ctx)
}

func parseClientAuth(tokens []string, restrs []TokenRestriction) (control.ClientAuthenticator, error) {
	switch {
	case len(restrs) == 0:
		restrs = make([]TokenRestriction, len(tokens))
	case len(tokens) != len(restrs):
		return nil, fmt.Errorf("client auth tokens (%d) does not match the number of restrictions (%d)", len(tokens), len(restrs))
	}

	auths := make([]selfhosted.ClientAuthentication, len(tokens))
	for i, r := range restrs {
		ips, err := restr.ParseIP(r.AllowCIDRs, r.DenyCIDRs)
		if err != nil {
			return nil, fmt.Errorf("client auth at %d ip restriction: %w", i, err)
		}
		names, err := restr.ParseName(r.NameMatches)
		if err != nil {
			return nil, fmt.Errorf("client auth at %d name restriction: %w", i, err)
		}
		role, err := parseRole(r.RoleMatches)
		if err != nil {
			return nil, fmt.Errorf("client auth at %d role restriction: %w", i, err)
		}
		auths[i] = selfhosted.ClientAuthentication{
			Token: tokens[i],
			IPs:   ips,
			Names: names,
			Role:  role,
		}
	}
	return selfhosted.NewClientAuthenticator(auths...), nil
}

func parseRelayAuth(tokens []string, restrs []IPRestriction) (control.RelayAuthenticator, error) {
	switch {
	case len(restrs) == 0:
		restrs = make([]IPRestriction, len(tokens))
	case len(tokens) != len(restrs):
		return nil, fmt.Errorf("relay auth tokens (%d) does not match the number of ip restrictions (%d)", len(tokens), len(restrs))
	}

	auths := make([]selfhosted.RelayAuthentication, len(tokens))
	for i, r := range restrs {
		ips, err := restr.ParseIP(r.AllowCIDRs, r.DenyCIDRs)
		if err != nil {
			return nil, fmt.Errorf("relay auth at %d ip restriction: %w", i, err)
		}
		auths[i] = selfhosted.RelayAuthentication{
			Token: tokens[i],
			IPs:   ips,
		}
	}

	return selfhosted.NewRelayAuthenticator(auths...), nil
}

func (c *ControlConfig) merge(o ControlConfig) {
	c.Cert = override(c.Cert, o.Cert)
	c.Key = override(c.Key, o.Key)

	c.ClientsAddr = override(c.ClientsAddr, o.ClientsAddr)
	c.ClientsIPRestriction.AllowCIDRs = overrides(c.ClientsIPRestriction.AllowCIDRs, o.ClientsIPRestriction.AllowCIDRs)
	c.ClientsIPRestriction.DenyCIDRs = overrides(c.ClientsIPRestriction.DenyCIDRs, o.ClientsIPRestriction.DenyCIDRs)
	if len(o.ClientsTokens) > 0 || o.ClientsTokensFile != "" { // new config completely overrides tokens
		c.ClientsTokens = o.ClientsTokens
		c.ClientsTokensFile = o.ClientsTokensFile
	}
	if len(c.ClientsTokenRestrictions) == len(o.ClientsTokenRestrictions) {
		for i := range c.ClientsTokenRestrictions {
			c.ClientsTokenRestrictions[i] = mergeTokenRestriction(c.ClientsTokenRestrictions[i], o.ClientsTokenRestrictions[i])
		}
	} else if len(o.ClientsTokenRestrictions) > 0 {
		c.ClientsTokenRestrictions = o.ClientsTokenRestrictions
	}

	c.RelaysAddr = override(c.RelaysAddr, o.RelaysAddr)
	c.RelaysIPRestriction.AllowCIDRs = overrides(c.RelaysIPRestriction.AllowCIDRs, o.RelaysIPRestriction.AllowCIDRs)
	c.RelaysIPRestriction.DenyCIDRs = overrides(c.RelaysIPRestriction.DenyCIDRs, o.RelaysIPRestriction.DenyCIDRs)
	if len(o.RelaysTokens) > 0 || o.RelaysTokensFile != "" { // new config completely overrides tokens
		c.RelaysTokens = o.RelaysTokens
		c.RelaysTokensFile = o.RelaysTokensFile
	}
	if len(c.RelaysTokenIPRestrictions) == len(o.RelaysTokenIPRestrictions) {
		for i := range c.RelaysTokenIPRestrictions {
			c.RelaysTokenIPRestrictions[i] = mergeIPRestriction(c.RelaysTokenIPRestrictions[i], o.RelaysTokenIPRestrictions[i])
		}
	} else if len(o.RelaysTokenIPRestrictions) > 0 {
		c.RelaysTokenIPRestrictions = o.RelaysTokenIPRestrictions
	}

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func mergeTokenRestriction(c, o TokenRestriction) TokenRestriction {
	return TokenRestriction{
		AllowCIDRs:  overrides(c.AllowCIDRs, o.AllowCIDRs),
		DenyCIDRs:   overrides(c.DenyCIDRs, o.DenyCIDRs),
		NameMatches: override(c.NameMatches, o.NameMatches),
		RoleMatches: override(c.RoleMatches, o.RoleMatches),
	}
}

func mergeIPRestriction(c, o IPRestriction) IPRestriction {
	return IPRestriction{
		AllowCIDRs: overrides(c.AllowCIDRs, o.AllowCIDRs),
		DenyCIDRs:  overrides(c.DenyCIDRs, o.DenyCIDRs),
	}
}

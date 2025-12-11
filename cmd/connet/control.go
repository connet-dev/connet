package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/restr"
	"github.com/connet-dev/connet/selfhosted"
	"github.com/connet-dev/connet/server"
	"github.com/spf13/cobra"
)

type ControlConfig struct {
	ClientsIngresses         []ControlIngress   `toml:"clients-ingress"`
	ClientsTokensFile        string             `toml:"clients-tokens-file"`
	ClientsTokens            []string           `toml:"clients-tokens"`
	ClientsTokenRestrictions []TokenRestriction `toml:"clients-token-restriction"`

	RelaysIngresses         []ControlIngress `toml:"relays-ingress"`
	RelaysTokensFile        string           `toml:"relays-tokens-file"`
	RelaysTokens            []string         `toml:"relays-tokens"`
	RelaysTokenRestrictions []IPRestriction  `toml:"relays-token-restriction"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

type ControlIngress struct {
	Addr string `toml:"addr"`
	Cert string `toml:"cert-file"`
	Key  string `toml:"key-file"`
	IPRestriction
}

type IPRestriction struct {
	AllowCIDRs []string `toml:"allow-cidrs"`
	DenyCIDRs  []string `toml:"deny-cidrs"`
}

type TokenRestriction struct {
	NameMatches string `toml:"name-matches"`
	RoleMatches string `toml:"role-matches"`
	IPRestriction
}

func controlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control",
		Short: "Run a connet control server",
	}
	cmd.Flags().SortFlags = false

	filenames := addConfigsFlag(cmd)

	var flagsConfig Config
	flagsConfig.addLogFlags(cmd)

	var commonIngress ControlIngress
	cmd.Flags().StringVar(&commonIngress.Cert, "cert-file", "", "default servers' TLS certificate file (pem format)")
	cmd.Flags().StringVar(&commonIngress.Key, "key-file", "", "default servers' TLS certificate private key file (pem format)")

	cmd.Flags().StringVar(&flagsConfig.Control.ClientsTokensFile, "clients-tokens-file", "", "file containing a list of client auth tokens (token per line)")
	cmd.Flags().StringArrayVar(&flagsConfig.Control.ClientsTokens, "clients-tokens", nil, "list of client auth tokens (fallback when 'client-tokens-file' is not specified)")

	var clientIngress ControlIngress
	cmd.Flags().StringVar(&clientIngress.Addr, "clients-addr", "", "clients server address to listen for connections (UDP/QUIC, [host]:port) (defaults to ':19190')")
	cmd.Flags().StringVar(&clientIngress.Cert, "clients-cert-file", "", "clients server TLS certificate file (pem format) (defaults to 'cert-file' if unspecified)")
	cmd.Flags().StringVar(&clientIngress.Key, "clients-key-file", "", "clients server TLS certificate key file (pem format) (defaults to 'key-file' if unspecified)")
	cmd.Flags().StringArrayVar(&clientIngress.AllowCIDRs, "clients-allow-cidr", nil, "list of allowed networks for client connections (CIDR format)")
	cmd.Flags().StringArrayVar(&clientIngress.DenyCIDRs, "clients-deny-cidr", nil, "list of denied networks for client connections (CIDR format)")

	cmd.Flags().StringVar(&flagsConfig.Control.RelaysTokensFile, "relays-tokens-file", "", "file containing a list of relay auth tokens (token per line)")
	cmd.Flags().StringArrayVar(&flagsConfig.Control.RelaysTokens, "relays-tokens", nil, "list of relay auth tokens (fallback when 'relay-tokens-file' is not specified)")

	var relayIngress ControlIngress
	cmd.Flags().StringVar(&relayIngress.Addr, "relays-addr", "", "relays server address to listen for connections (UDP/QUIC, [host]:port) (defaults to ':19189')")
	cmd.Flags().StringVar(&relayIngress.Cert, "relays-cert-file", "", "relays server TLS certificate file (pem format) (defaults to 'cert-file' if unspecified)")
	cmd.Flags().StringVar(&relayIngress.Key, "relays-key-file", "", "relays server TLS certificate key file (pem format) (defaults to 'key-file' if unspecified)")
	cmd.Flags().StringArrayVar(&relayIngress.AllowCIDRs, "relays-allow-cidr", nil, "list of allowed networks for relay connections (CIDR format)")
	cmd.Flags().StringArrayVar(&relayIngress.DenyCIDRs, "relays-deny-cidr", nil, "list of denied networks for relay connections (CIDR format)")

	addStatusAddrFlag(cmd, &flagsConfig.Control.StatusAddr)
	addStoreDirFlag(cmd, &flagsConfig.Control.StoreDir)

	cmd.RunE = wrapErr("run connet control server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		clientIngress = clientIngress.merge(commonIngress)
		if !clientIngress.isZero() {
			flagsConfig.Control.ClientsIngresses = append(flagsConfig.Control.ClientsIngresses, clientIngress)
		}

		relayIngress = relayIngress.merge(commonIngress)
		if !relayIngress.isZero() {
			flagsConfig.Control.RelaysIngresses = append(flagsConfig.Control.RelaysIngresses, relayIngress)
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
	var err error

	controlCfg := control.Config{
		Logger: logger,
	}

	var usedClientsDefault bool
	for ix, ingressCfg := range cfg.ClientsIngresses {
		if ingressCfg.Addr == "" && !usedClientsDefault {
			ingressCfg.Addr = ":19190"
			usedClientsDefault = true
		}
		if ingress, err := ingressCfg.parse(); err != nil {
			return fmt.Errorf("parse client ingress at %d: %w", ix, err)
		} else {
			controlCfg.ClientsIngress = append(controlCfg.ClientsIngress, ingress)
		}
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

	var usedRelaysDefault bool
	for ix, ingressCfg := range cfg.RelaysIngresses {
		if ingressCfg.Addr == "" && !usedRelaysDefault {
			ingressCfg.Addr = ":19189"
			usedRelaysDefault = true
		}
		if ingress, err := ingressCfg.parse(); err != nil {
			return fmt.Errorf("parse relay ingress at %d: %w", ix, err)
		} else {
			controlCfg.RelaysIngress = append(controlCfg.RelaysIngress, ingress)
		}
	}

	relayTokens := cfg.RelaysTokens
	if cfg.RelaysTokensFile != "" {
		relayTokens, err = loadTokens(cfg.RelaysTokensFile)
		if err != nil {
			return fmt.Errorf("load relays tokens: %w", err)
		}
	}
	controlCfg.RelaysAuth, err = parseRelayAuth(relayTokens, cfg.RelaysTokenRestrictions)
	if err != nil {
		return err
	}

	var statusAddr *net.TCPAddr
	if cfg.StatusAddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("resolve status address: %w", err)
		}
		statusAddr = addr
	}

	if cfg.StoreDir == "" {
		dir, err := server.StoreDirFromEnvPrefixed("connet-control-")
		if err != nil {
			return fmt.Errorf("store dir from env: %w", err)
		}
		logger.Info("using default store directory", "dir", dir)
		cfg.StoreDir = dir
	}
	controlCfg.Stores = control.NewFileStores(cfg.StoreDir)

	srv, err := control.NewServer(controlCfg)
	if err != nil {
		return fmt.Errorf("create control server: %w", err)
	}
	return runWithStatus(ctx, srv, statusAddr, logger)
}

func (cfg ControlIngress) parse() (control.Ingress, error) {
	return control.NewIngressBuilder().
		WithAddrFrom(cfg.Addr).
		WithTLSCertFrom(cfg.Cert, cfg.Key).
		WithRestrFrom(cfg.AllowCIDRs, cfg.DenyCIDRs).
		Ingress()
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
	c.ClientsIngresses = mergeSlices(c.ClientsIngresses, o.ClientsIngresses)
	if len(o.ClientsTokens) > 0 || o.ClientsTokensFile != "" { // new config completely overrides tokens
		c.ClientsTokens = o.ClientsTokens
		c.ClientsTokensFile = o.ClientsTokensFile
	}
	c.ClientsTokenRestrictions = mergeSlices(c.ClientsTokenRestrictions, o.ClientsTokenRestrictions)

	c.RelaysIngresses = mergeSlices(c.RelaysIngresses, o.RelaysIngresses)
	if len(o.RelaysTokens) > 0 || o.RelaysTokensFile != "" { // new config completely overrides tokens
		c.RelaysTokens = o.RelaysTokens
		c.RelaysTokensFile = o.RelaysTokensFile
	}
	c.RelaysTokenRestrictions = mergeSlices(c.RelaysTokenRestrictions, o.RelaysTokenRestrictions)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func (c ControlIngress) merge(o ControlIngress) ControlIngress {
	return ControlIngress{
		Addr:          override(c.Addr, o.Addr),
		Cert:          override(c.Cert, o.Cert),
		Key:           override(c.Key, o.Key),
		IPRestriction: c.IPRestriction.merge(o.IPRestriction),
	}
}

func (c TokenRestriction) merge(o TokenRestriction) TokenRestriction {
	return TokenRestriction{
		NameMatches:   override(c.NameMatches, o.NameMatches),
		RoleMatches:   override(c.RoleMatches, o.RoleMatches),
		IPRestriction: c.IPRestriction.merge(o.IPRestriction),
	}
}

func (c IPRestriction) merge(o IPRestriction) IPRestriction {
	return IPRestriction{
		AllowCIDRs: overrides(c.AllowCIDRs, o.AllowCIDRs),
		DenyCIDRs:  overrides(c.DenyCIDRs, o.DenyCIDRs),
	}
}

func (s ControlIngress) isZero() bool {
	return s.Addr == "" && s.Cert == "" && s.Key == "" && len(s.AllowCIDRs) == 0 && len(s.DenyCIDRs) == 0
}

var _ = TokenRestriction.merge

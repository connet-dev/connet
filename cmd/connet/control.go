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
	ClientsIngresses         []Ingress          `toml:"clients-ingress"`
	ClientsTokens            []string           `toml:"clients-tokens"`
	ClientsTokensFile        string             `toml:"clients-tokens-file"`
	ClientsTokenRestrictions []TokenRestriction `toml:"clients-token-restriction"`

	RelaysIngresses           []Ingress       `toml:"relays-ingress"`
	RelaysTokens              []string        `toml:"relays-tokens"`
	RelaysTokensFile          string          `toml:"relays-tokens-file"`
	RelaysTokenIPRestrictions []IPRestriction `toml:"relays-token-ip-restriction"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

type Ingress struct {
	Addr  string        `toml:"addr"`
	Cert  string        `toml:"cert-file"`
	Key   string        `toml:"key-file"`
	Restr IPRestriction `toml:"ip-restriction"`
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
	cmd.Flags().SortFlags = false

	filenames := cmd.Flags().StringArray("config", nil, "config file to load, can be passed mulitple times")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	var commonIngress Ingress
	cmd.Flags().StringVar(&commonIngress.Cert, "cert-file", "", "control server cert to use (both clients and relays)")
	cmd.Flags().StringVar(&commonIngress.Key, "key-file", "", "control server key to use (both clients and relays)")

	var clientIngress Ingress
	cmd.Flags().StringVar(&clientIngress.Addr, "clients-addr", "", "control client server addr to use")
	cmd.Flags().StringVar(&clientIngress.Cert, "clients-cert-file", "", "control server cert to use for clients")
	cmd.Flags().StringVar(&clientIngress.Key, "clients-key-file", "", "control server key to use for clients")
	cmd.Flags().StringSliceVar(&clientIngress.Restr.AllowCIDRs, "clients-allow-cidr", nil, "cidr to allow client connections from")
	cmd.Flags().StringSliceVar(&clientIngress.Restr.DenyCIDRs, "clients-deny-cidr", nil, "cidr to deny client connections from")

	cmd.Flags().StringArrayVar(&flagsConfig.Control.ClientsTokens, "clients-tokens", nil, "client tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Control.ClientsTokensFile, "clients-tokens-file", "", "client tokens file to load")

	var relayIngress Ingress
	cmd.Flags().StringVar(&relayIngress.Addr, "relays-addr", "", "control relay server addr to use")
	cmd.Flags().StringVar(&relayIngress.Cert, "relays-cert-file", "", "control server cert to use for relays")
	cmd.Flags().StringVar(&relayIngress.Key, "relays-key-file", "", "control server key to use for relays")
	cmd.Flags().StringSliceVar(&relayIngress.Restr.AllowCIDRs, "relays-allow-cidr", nil, "cidr to allow relay connections from")
	cmd.Flags().StringSliceVar(&relayIngress.Restr.DenyCIDRs, "relays-deny-cidr", nil, "cidr to deny relay connections from")

	cmd.Flags().StringArrayVar(&flagsConfig.Control.RelaysTokens, "relays-tokens", nil, "relay tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Control.RelaysTokensFile, "relays-tokens-file", "", "relay tokens file to load")

	cmd.Flags().StringVar(&flagsConfig.Control.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Control.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet control server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		clientIngress = mergeIngress(clientIngress, commonIngress)
		if !clientIngress.isZero() {
			flagsConfig.Control.ClientsIngresses = append(flagsConfig.Control.ClientsIngresses, clientIngress)
		}

		relayIngress = mergeIngress(relayIngress, commonIngress)
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

	for ix, ingressCfg := range cfg.ClientsIngresses {
		if ingressCfg.Addr == "" {
			ingressCfg.Addr = ":19190"
		}
		if ingress, err := parseIngress(ingressCfg); err != nil {
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

	for ix, ingressCfg := range cfg.RelaysIngresses {
		if ingressCfg.Addr == "" {
			ingressCfg.Addr = ":19189"
		}
		if ingress, err := parseIngress(ingressCfg); err != nil {
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
	controlCfg.RelaysAuth, err = parseRelayAuth(relayTokens, cfg.RelaysTokenIPRestrictions)
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
	return runWithStatus(ctx, srv, statusAddr, logger)
}

func parseIngress(cfg Ingress) (control.Ingress, error) {
	var result control.Ingress

	clientAddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return control.Ingress{}, fmt.Errorf("resolve udp address: %w", err)
	}
	result.Addr = clientAddr

	if len(cfg.Restr.AllowCIDRs) > 0 || len(cfg.Restr.DenyCIDRs) > 0 {
		iprestr, err := restr.ParseIP(cfg.Restr.AllowCIDRs, cfg.Restr.DenyCIDRs)
		if err != nil {
			return control.Ingress{}, fmt.Errorf("parse restrictions: %w", err)
		}
		result.Restr = iprestr
	}

	result.TLS = &tls.Config{}
	if cfg.Cert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return control.Ingress{}, fmt.Errorf("load server certificate: %w", err)
		}
		result.TLS.Certificates = append(result.TLS.Certificates, cert)
	}

	return result, nil
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
	if len(c.ClientsIngresses) == len(o.ClientsIngresses) {
		for i := range c.ClientsIngresses {
			c.ClientsIngresses[i] = mergeIngress(c.ClientsIngresses[i], o.ClientsIngresses[i])
		}
	} else if len(o.ClientsIngresses) > 0 {
		c.ClientsIngresses = o.ClientsIngresses
	}

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

	if len(c.RelaysIngresses) == len(o.RelaysIngresses) {
		for i := range c.RelaysIngresses {
			c.RelaysIngresses[i] = mergeIngress(c.RelaysIngresses[i], o.RelaysIngresses[i])
		}
	} else if len(o.RelaysIngresses) > 0 {
		c.RelaysIngresses = o.RelaysIngresses
	}

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

func mergeIngress(c, o Ingress) Ingress {
	return Ingress{
		Addr: override(c.Addr, o.Addr),
		Cert: override(c.Cert, o.Cert),
		Key:  override(c.Key, o.Key),
		Restr: IPRestriction{
			AllowCIDRs: overrides(c.Restr.AllowCIDRs, o.Restr.AllowCIDRs),
			DenyCIDRs:  overrides(c.Restr.DenyCIDRs, o.Restr.DenyCIDRs),
		},
	}
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

func (s Ingress) isZero() bool {
	return s.Addr == "" && s.Cert == "" && s.Key == "" && len(s.Restr.AllowCIDRs) == 0 && len(s.Restr.DenyCIDRs) == 0
}

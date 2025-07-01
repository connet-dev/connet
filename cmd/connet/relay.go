package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/connet-dev/connet/relay"
	"github.com/spf13/cobra"
)

type RelayConfig struct {
	Token     string `toml:"token"`
	TokenFile string `toml:"token-file"`

	Ingresses []RelayIngress `toml:"ingress"`

	ControlAddr string `toml:"control-addr"`
	ControlCAs  string `toml:"control-cas"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

type RelayIngress struct {
	Addr      string   `toml:"addr"`
	Hostports []string `toml:"hostports"`
	IPRestriction
}

func relayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "run connet relay server",
	}
	cmd.Flags().SortFlags = false

	filenames := cmd.Flags().StringArray("config", nil, "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.Token, "token", "", "token to use")
	cmd.Flags().StringVar(&flagsConfig.Relay.TokenFile, "token-file", "", "token file to use")

	var ingress RelayIngress
	cmd.Flags().StringVar(&ingress.Addr, "addr", "", "server addr to use")
	cmd.Flags().StringArrayVar(&ingress.Hostports, "hostport", nil, "server public host[:port] to use (if port is missing will use addr's port)")
	cmd.Flags().StringArrayVar(&ingress.AllowCIDRs, "allow-cidr", nil, "cidr to allow client connections from")
	cmd.Flags().StringArrayVar(&ingress.DenyCIDRs, "deny-cidr", nil, "cidr to deny client connections from")

	cmd.Flags().StringVar(&flagsConfig.Relay.ControlAddr, "control-addr", "", "control server address to connect")
	cmd.Flags().StringVar(&flagsConfig.Relay.ControlCAs, "control-cas", "", "control server CAs to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Relay.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet relay server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if !ingress.isZero() {
			flagsConfig.Relay.Ingresses = append(flagsConfig.Relay.Ingresses, ingress)
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

	if len(cfg.Ingresses) == 0 {
		cfg.Ingresses = append(cfg.Ingresses, RelayIngress{})
	}

	var usedDefault bool
	for ix, ingressCfg := range cfg.Ingresses {
		if ingressCfg.Addr == "" && !usedDefault {
			ingressCfg.Addr = ":19191"
			usedDefault = true
		}
		if ingress, err := ingressCfg.parse(); err != nil {
			return fmt.Errorf("parse ingress at %d: %w", ix, err)
		} else {
			relayCfg.Ingress = append(relayCfg.Ingress, ingress)
		}
	}

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

	var statusAddr *net.TCPAddr
	if cfg.StatusAddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("resolve status address: %w", err)
		}
		statusAddr = addr
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
	return runWithStatus(ctx, srv, statusAddr, logger)
}

func (cfg RelayIngress) parse() (relay.Ingress, error) {
	bldr := relay.NewIngressBuilder().
		WithAddrFrom(cfg.Addr).WithRestrFrom(cfg.AllowCIDRs, cfg.DenyCIDRs)

	for ix, hp := range cfg.Hostports {
		bldr = bldr.WithHostportFrom(hp)
		if bldr.Error() != nil {
			return relay.Ingress{}, fmt.Errorf("parse hostport at %d: %w", ix, bldr.Error())
		}
	}

	return bldr.Ingress()
}

func (c *RelayConfig) merge(o RelayConfig) {
	if o.Token != "" || o.TokenFile != "" { // new config completely overrides token
		c.Token = o.Token
		c.TokenFile = o.TokenFile
	}

	c.Ingresses = mergeSlices(c.Ingresses, o.Ingresses)

	c.ControlAddr = override(c.ControlAddr, o.ControlAddr)
	c.ControlCAs = override(c.ControlCAs, o.ControlCAs)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func (c RelayIngress) merge(o RelayIngress) RelayIngress {
	return RelayIngress{
		Addr:          override(c.Addr, o.Addr),
		Hostports:     overrides(c.Hostports, o.Hostports),
		IPRestriction: c.IPRestriction.merge(o.IPRestriction),
	}
}

func (s RelayIngress) isZero() bool {
	return s.Addr == "" && len(s.Hostports) == 0 && len(s.AllowCIDRs) == 0 && len(s.DenyCIDRs) == 0
}

var _ = RelayIngress.merge

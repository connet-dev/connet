package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/connet-dev/connet"
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/nat"
	"github.com/connet-dev/connet/reliable"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type CombinedConfig struct {
	Ingress           ControlIngress     `toml:"ingress"`
	Tokens            []string           `toml:"tokens"`
	TokensFile        string             `toml:"tokens-file"`
	TokenRestrictions []TokenRestriction `toml:"token-restriction"`

	DirectAddr   string                       `toml:"direct-addr"`
	Destinations map[string]DestinationConfig `toml:"destinations"`
	Sources      map[string]SourceConfig      `toml:"sources"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

func combinedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "combined",
		Short: "run connet combined control server and client",
	}
	cmd.Flags().SortFlags = false

	filenames := cmd.Flags().StringArray("config", nil, "config file to load, can be passed multiple times")

	cmd.RunE = wrapErr("run connet combined", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		// TODO set any defaults

		logger, err := logger(cfg)
		if err != nil {
			return fmt.Errorf("configure logger: %w", err)
		}

		return combinedRun(cmd.Context(), cfg.Combined, logger)
	})

	return cmd
}

func combinedRun(ctx context.Context, cfg CombinedConfig, logger *slog.Logger) error {
	runCfg, err := parseCombinedConfig(cfg, logger)
	if err != nil {
		return err
	}

	svr, err := control.NewServer(runCfg.control)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return svr.Run(ctx) })

	// TODO should wait for server status
	if err := reliable.Wait(ctx, time.Second); err != nil {
		return err
	}

	cl, err := connet.Connect(ctx, runCfg.client...)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	runCfg.destinations.schedule(ctx, cl, g)
	runCfg.sources.schedule(ctx, cl, g)

	// TODO run combined status

	return g.Wait()
}

type combinedConfig struct {
	control      control.Config
	client       []connet.ClientOption
	destinations *destinationsConfig
	sources      *sourcesConfig
	statusAddr   *net.TCPAddr
}

func parseCombinedConfig(cfg CombinedConfig, logger *slog.Logger) (*combinedConfig, error) {
	var err error

	controlCfg := control.Config{
		Logger: logger,
	}

	if cfg.Ingress.Addr == "" {
		cfg.Ingress.Addr = ":19190"
	}
	if ingress, err := cfg.Ingress.parse(); err != nil {
		return nil, fmt.Errorf("parse client ingress: %w", err)
	} else {
		controlCfg.ClientsIngress = append(controlCfg.ClientsIngress, ingress)
	}

	clientTokens := cfg.Tokens
	if cfg.TokensFile != "" {
		clientTokens, err = loadTokens(cfg.TokensFile)
		if err != nil {
			return nil, fmt.Errorf("load clients tokens: %w", err)
		}
	}

	// TODO add local client token/restr
	clientTokens = append(clientTokens, "xxxxx")
	if len(cfg.TokenRestrictions) > 0 {
		cfg.TokenRestrictions = append(cfg.TokenRestrictions, TokenRestriction{})
	}

	controlCfg.ClientsAuth, err = parseClientAuth(clientTokens, cfg.TokenRestrictions)
	if err != nil {
		return nil, err
	}

	var statusAddr *net.TCPAddr
	if cfg.StatusAddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve status address: %w", err)
		}
		statusAddr = addr
	}

	if cfg.StoreDir == "" {
		dir, err := connet.StoreDirFromEnv("connet-combined-")
		if err != nil {
			return nil, fmt.Errorf("store dir from env: %w", err)
		}
		logger.Info("using default store directory", "dir", dir)
		cfg.StoreDir = dir
	}
	controlCfg.Stores = control.NewFileStores(cfg.StoreDir)

	var serverName string
	serverCert := controlCfg.ClientsIngress[0].TLS.Certificates[0].Leaf
	if len(serverCert.DNSNames) > 0 {
		serverName = serverCert.DNSNames[0]
	} else if len(serverCert.IPAddresses) > 0 {
		serverName = serverCert.IPAddresses[0].String()
	}

	opts := []connet.ClientOption{
		connet.ClientToken("xxxxx"),
		connet.ClientControlAddress(serverName),
		connet.ClientControlCAs(cfg.Ingress.Cert),
		connet.ClientNatPMPConfig(nat.PMPConfig{Disabled: true}),
	}

	if cfg.DirectAddr != "" {
		opts = append(opts, connet.ClientDirectAddress(cfg.DirectAddr))
	}

	// TODO direct stateless reset in store-dir
	opts = append(opts, connet.ClientDirectStatelessResetKeyFileCreate("stateless-reset-client.key"))

	dcfg, err := parseDestinations(cfg.Destinations, logger, nil)
	if err != nil {
		return nil, err
	}

	scfg, err := parseSources(cfg.Sources, logger, nil)
	if err != nil {
		return nil, err
	}

	opts = append(opts, connet.ClientLogger(logger))

	return &combinedConfig{
		control:      controlCfg,
		client:       opts,
		destinations: dcfg,
		sources:      scfg,
		statusAddr:   statusAddr,
	}, nil
}

func (c *CombinedConfig) merge(o CombinedConfig) {
	c.Ingress = c.Ingress.merge(o.Ingress)
	if len(o.Tokens) > 0 || o.TokensFile != "" { // new config completely overrides tokens
		c.Tokens = o.Tokens
		c.TokensFile = o.TokensFile
	}
	c.TokenRestrictions = mergeSlices(c.TokenRestrictions, o.TokenRestrictions)

	c.DirectAddr = override(c.DirectAddr, o.DirectAddr)
	for k, v := range o.Destinations {
		if c.Destinations == nil {
			c.Destinations = map[string]DestinationConfig{}
		}
		c.Destinations[k] = c.Destinations[k].merge(v)
	}

	for k, v := range o.Sources {
		if c.Sources == nil {
			c.Sources = map[string]SourceConfig{}
		}
		c.Sources[k] = c.Sources[k].merge(v)
	}

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

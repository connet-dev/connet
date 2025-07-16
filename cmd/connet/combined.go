package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/connet-dev/connet"
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/nat"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/statusc"
	"github.com/mr-tron/base58"
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

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Combined.Ingress.Addr, "ingress-addr", "", "control server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Combined.Ingress.Cert, "ingress-cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Combined.Ingress.Key, "ingress-key-file", "", "control server key to use")
	cmd.Flags().StringArrayVar(&flagsConfig.Combined.Ingress.AllowCIDRs, "ingress-allow-cidr", nil, "cidr to allow client connections from")
	cmd.Flags().StringArrayVar(&flagsConfig.Combined.Ingress.DenyCIDRs, "ingress-deny-cidr", nil, "cidr to deny client connections from")

	cmd.Flags().StringArrayVar(&flagsConfig.Combined.Tokens, "tokens", nil, "tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Combined.TokensFile, "tokens-file", "", "tokens file to load")

	cmd.Flags().StringVar(&flagsConfig.Combined.DirectAddr, "direct-addr", "", "local client direct server address to listen")

	var dstName string
	var dstCfg DestinationConfig
	cmd.Flags().StringVar(&dstName, "dst-name", "", "local client destination name")
	cmd.Flags().StringVar(&dstCfg.URL, "dst-url", "", "local client destination url (scheme describes the destination)")
	cmd.Flags().StringVar(&dstCfg.CAsFile, "dst-cas-file", "", "local client destination client tls certificate authorities file")

	var srcName string
	var srcCfg SourceConfig
	cmd.Flags().StringVar(&srcName, "src-name", "", "local client source name")
	cmd.Flags().StringVar(&srcCfg.URL, "src-url", "", "local client source url (scheme describes server type)")
	cmd.Flags().StringVar(&srcCfg.CertFile, "src-cert-file", "", "local client source server tls cert file")
	cmd.Flags().StringVar(&srcCfg.KeyFile, "src-key-file", "", "local client source server tls key file")

	cmd.Flags().StringVar(&flagsConfig.Combined.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Combined.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet combined", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if dstName != "" {
			flagsConfig.Combined.Destinations = map[string]DestinationConfig{dstName: dstCfg}
		}
		if srcName != "" {
			flagsConfig.Combined.Sources = map[string]SourceConfig{srcName: srcCfg}
		}
		cfg.merge(flagsConfig)

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

	srv, err := control.NewServer(runCfg.control)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return srv.Run(ctx) })

	// TODO should wait for server status
	if err := reliable.Wait(ctx, 100*time.Millisecond); err != nil {
		return err
	}

	cl, err := connet.Connect(ctx, runCfg.client...)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	runCfg.destinations.schedule(ctx, cl, g)
	runCfg.sources.schedule(ctx, cl, g)

	if runCfg.statusAddr != nil {
		g.Go(func() error {
			logger.Debug("running status server", "addr", runCfg.statusAddr)
			return statusc.Run(ctx, runCfg.statusAddr, func(ctx context.Context) (CombinedStatus, error) {
				controlStat, err := srv.Status(ctx)
				if err != nil {
					return CombinedStatus{}, err
				}
				clientStat, err := cl.Status(ctx)
				if err != nil {
					return CombinedStatus{}, err
				}

				return CombinedStatus{controlStat, clientStat}, nil
			})
		})
	}

	return g.Wait()
}

type CombinedStatus struct {
	Control control.Status      `json:"control"`
	Client  connet.ClientStatus `json:"client"`
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

	clientToken, err := genClientToken()
	if err != nil {
		return nil, fmt.Errorf("create client token: %w", err)
	}

	clientTokens = append(clientTokens, clientToken)
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

	opts := []connet.ClientOption{
		connet.ClientToken(clientToken),
		connet.ClientControlAddress(controlCfg.ClientsIngress[0].ExternalAddress()),
		connet.ClientControlCAs(cfg.Ingress.Cert),
		connet.ClientNatPMPConfig(nat.PMPConfig{Disabled: true}),
	}

	if cfg.DirectAddr != "" {
		opts = append(opts, connet.ClientDirectAddress(cfg.DirectAddr))
	}

	statelessKeyFile := filepath.Join(cfg.StoreDir, "client-stateless-reset.key")
	opts = append(opts, connet.ClientDirectStatelessResetKeyFileCreate(statelessKeyFile))

	dcfg, err := parseDestinations(cfg.Destinations, logger, nil)
	if err != nil {
		return nil, err
	}
	for name, dst := range dcfg.destinations {
		dst.Route = model.RouteDirect
		dcfg.destinations[name] = dst
	}

	scfg, err := parseSources(cfg.Sources, logger, nil)
	if err != nil {
		return nil, err
	}
	for name, src := range scfg.sources {
		src.Route = model.RouteDirect
		scfg.sources[name] = src
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

func genClientToken() (string, error) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return "", fmt.Errorf("generate client token key: %w", err)
	}
	return base58.Encode(key[:]), nil
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

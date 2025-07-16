package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/nat"
	"github.com/connet-dev/connet/statusc"
	"github.com/mr-tron/base58"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type ClientConfig struct {
	Token     string `toml:"token"`
	TokenFile string `toml:"token-file"`

	ServerAddr string `toml:"server-addr"`
	ServerCAs  string `toml:"server-cas"`

	DirectAddr         string `toml:"direct-addr"`
	DirectResetKey     string `toml:"direct-stateless-reset-key"`
	DirectResetKeyFile string `toml:"direct-stateless-reset-key-file"`
	StatusAddr         string `toml:"status-addr"`
	NatPMP             string `toml:"nat-pmp"`

	RelayEncryptions []string                     `toml:"relay-encryptions"`
	Destinations     map[string]DestinationConfig `toml:"destinations"`
	Sources          map[string]SourceConfig      `toml:"sources"`
}

type DestinationConfig struct {
	Route             string   `toml:"route"`
	RelayEncryptions  []string `toml:"relay-encryptions"`
	ProxyProtoVersion string   `toml:"proxy-proto-version"`

	URL      string `toml:"url"`
	CAsFile  string `toml:"cas-file"`  // tls/https server certificate authority, literal "insecure-skip-verify" to skip
	CertFile string `toml:"cert-file"` // mutual tls client cert
	KeyFile  string `toml:"key-file"`  // mutual tls client key
}

type SourceConfig struct {
	Route            string   `toml:"route"`
	RelayEncryptions []string `toml:"relay-encryptions"`

	URL      string `toml:"url"`
	CertFile string `toml:"cert-file"` // tls/https server cert
	KeyFile  string `toml:"key-file"`  // tls/https server key
	CAsFile  string `toml:"cas-file"`  // mutual tls client certificate authority
}

func clientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "connet",
		Short:         "connet is a reverse proxy/nat traversal tool",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().SortFlags = false

	filenames := cmd.Flags().StringArray("config", nil, "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Client.Token, "token", "", "token to use")
	cmd.Flags().StringVar(&flagsConfig.Client.TokenFile, "token-file", "", "token file to use")

	cmd.Flags().StringVar(&flagsConfig.Client.ServerAddr, "server-addr", "", "control server address to connect")
	cmd.Flags().StringVar(&flagsConfig.Client.ServerCAs, "server-cas", "", "control server CAs to use")

	cmd.Flags().StringVar(&flagsConfig.Client.DirectAddr, "direct-addr", "", "direct server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Client.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Client.NatPMP, "nat-pmp", "", "nat-pmp behavior ('disabled', 'system', 'dial')")

	var dstName string
	var dstCfg DestinationConfig
	cmd.Flags().StringVar(&dstName, "dst-name", "", "destination name")
	cmd.Flags().StringVar(&dstCfg.Route, "dst-route", "", "destination route")
	cmd.Flags().StringSliceVar(&dstCfg.RelayEncryptions, "dst-relay-encryption", nil, "destination relay encryptions")
	cmd.Flags().StringVar(&dstCfg.URL, "dst-url", "", "destination url (scheme describes the destination)")
	cmd.Flags().StringVar(&dstCfg.CAsFile, "dst-cas-file", "", "destination client tls certificate authorities file")

	var srcName string
	var srcCfg SourceConfig
	cmd.Flags().StringVar(&srcName, "src-name", "", "source name")
	cmd.Flags().StringVar(&srcCfg.Route, "src-route", "", "source route")
	cmd.Flags().StringSliceVar(&srcCfg.RelayEncryptions, "src-relay-encryption", nil, "source relay encryptions")
	cmd.Flags().StringVar(&srcCfg.URL, "src-url", "", "source url (scheme describes server type)")
	cmd.Flags().StringVar(&srcCfg.CertFile, "src-cert-file", "", "source server tls cert file")
	cmd.Flags().StringVar(&srcCfg.KeyFile, "src-key-file", "", "source server tls key file")

	cmd.RunE = wrapErr("run connet client", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfigs(*filenames)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if dstName != "" {
			flagsConfig.Client.Destinations = map[string]DestinationConfig{dstName: dstCfg}
		}
		if srcName != "" {
			flagsConfig.Client.Sources = map[string]SourceConfig{srcName: srcCfg}
		}

		cfg.merge(flagsConfig)

		logger, err := logger(cfg)
		if err != nil {
			return fmt.Errorf("configure logger: %w", err)
		}

		return clientRun(cmd.Context(), cfg.Client, logger)
	})

	return cmd
}

type runnable interface {
	Run(ctx context.Context) error
}

type newrunnable[T any] func(t T) runnable

func clientRun(ctx context.Context, cfg ClientConfig, logger *slog.Logger) error {
	var opts []connet.ClientOption

	if cfg.TokenFile != "" {
		tokens, err := loadTokens(cfg.TokenFile)
		if err != nil {
			return err
		}
		opts = append(opts, connet.ClientToken(tokens[0]))
	} else {
		opts = append(opts, connet.ClientToken(cfg.Token))
	}

	if cfg.ServerAddr != "" {
		opts = append(opts, connet.ClientControlAddress(cfg.ServerAddr))
	}
	if cfg.ServerCAs != "" {
		opts = append(opts, connet.ClientControlCAs(cfg.ServerCAs))
	}

	if cfg.DirectAddr != "" {
		opts = append(opts, connet.ClientDirectAddress(cfg.DirectAddr))
	}

	if cfg.DirectResetKeyFile != "" {
		opts = append(opts, connet.ClientDirectStatelessResetKeyFile(cfg.DirectResetKeyFile))
	} else if cfg.DirectResetKey != "" {
		keyBytes, err := base58.Decode(cfg.DirectResetKey)
		if err != nil {
			return fmt.Errorf("decode stateless reset key: %w", err)
		}
		if len(keyBytes) < 32 {
			return fmt.Errorf("stateless reset key len %d", len(keyBytes))
		}
		key := quic.StatelessResetKey(keyBytes)
		opts = append(opts, connet.ClientDirectStatelessResetKey(&key))
	}

	var statusAddr *net.TCPAddr
	if cfg.StatusAddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("resolve status address: %w", err)
		}
		statusAddr = addr
	}

	var pmpCfg nat.PMPConfig
	switch cfg.NatPMP {
	case "", "system":
		pmpCfg.LocalResolver = nat.LocalIPSystemResolver()
		pmpCfg.GatewayResolver = nat.GatewayIPSystemResolver()
	case "disabled":
		pmpCfg.Disabled = true
	case "dial":
		pmpCfg.LocalResolver = nat.LocalIPDialResolver(cfg.ServerAddr)
		pmpCfg.GatewayResolver = nat.GatewayIPNet24Resolver()
	default:
		return fmt.Errorf("invalid Nat-PMP config option: %s", cfg.NatPMP)
	}
	opts = append(opts, connet.ClientNatPMPConfig(pmpCfg))

	var defaultRelayEncryptions = []model.EncryptionScheme{model.NoEncryption}
	if len(cfg.RelayEncryptions) > 0 {
		res, err := parseEncryptionSchemes(cfg.RelayEncryptions)
		if err != nil {
			return fmt.Errorf("parse relay encryptions: %w", err)
		}
		defaultRelayEncryptions = res
	}

	dcfg, err := parseDestinations(cfg.Destinations, logger, defaultRelayEncryptions)
	if err != nil {
		return err
	}

	scfg, err := parseSources(cfg.Sources, logger, defaultRelayEncryptions)
	if err != nil {
		return err
	}

	opts = append(opts, connet.ClientLogger(logger))

	cl, err := connet.Connect(ctx, opts...)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	if statusAddr != nil {
		g.Go(func() error {
			logger.Debug("running status server", "addr", statusAddr)
			return statusc.Run(ctx, statusAddr, cl.Status)
		})
	}

	dcfg.schedule(ctx, cl, g)
	scfg.schedule(ctx, cl, g)

	return g.Wait()
}

func parseRouteOption(s string) (model.RouteOption, error) {
	if s == "" {
		return model.RouteAny, nil
	}
	return model.ParseRouteOption(s)
}

func parseProxyVersion(s string) (model.ProxyVersion, error) {
	if s == "" {
		return model.ProxyNone, nil
	}
	return model.ParseProxyVersion(s)
}

func parseRole(s string) (model.Role, error) {
	if s == "" {
		return model.UnknownRole, nil
	}
	return model.ParseRole(s)
}

func parseEncryptionSchemes(s []string) ([]model.EncryptionScheme, error) {
	encs := make([]model.EncryptionScheme, len(s))
	for i, si := range s {
		enc, err := model.ParseEncryptionScheme(si)
		if err != nil {
			return nil, err
		}
		encs[i] = enc
	}
	return encs, nil
}

func (c *ClientConfig) merge(o ClientConfig) {
	if o.Token != "" || o.TokenFile != "" { // new config completely overrides token
		c.Token = o.Token
		c.TokenFile = o.TokenFile
	}

	c.ServerAddr = override(c.ServerAddr, o.ServerAddr)
	c.ServerCAs = override(c.ServerCAs, o.ServerCAs)

	c.DirectAddr = override(c.DirectAddr, o.DirectAddr)
	if o.DirectResetKey != "" || o.DirectResetKeyFile != "" {
		c.DirectResetKey = o.DirectResetKey
		c.DirectResetKeyFile = o.DirectResetKeyFile
	}
	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.NatPMP = override(c.NatPMP, o.NatPMP)

	c.RelayEncryptions = overrides(c.RelayEncryptions, o.RelayEncryptions)

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
}

func (c DestinationConfig) merge(o DestinationConfig) DestinationConfig {
	return DestinationConfig{
		Route:             override(c.Route, o.Route),
		RelayEncryptions:  overrides(c.RelayEncryptions, o.RelayEncryptions),
		ProxyProtoVersion: override(c.ProxyProtoVersion, o.ProxyProtoVersion),

		URL:      override(c.URL, o.URL),
		CAsFile:  override(c.CAsFile, o.CAsFile),
		CertFile: override(c.CertFile, o.CertFile),
		KeyFile:  override(c.KeyFile, o.KeyFile),
	}
}

func (c SourceConfig) merge(o SourceConfig) SourceConfig {
	return SourceConfig{
		Route:            override(c.Route, o.Route),
		RelayEncryptions: overrides(c.RelayEncryptions, o.RelayEncryptions),

		URL:      override(c.URL, o.URL),
		CAsFile:  override(c.CAsFile, o.CAsFile),
		CertFile: override(c.CertFile, o.CertFile),
		KeyFile:  override(c.KeyFile, o.KeyFile),
	}
}

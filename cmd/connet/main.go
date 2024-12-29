package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/connet-dev/connet"
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/relay"
	"github.com/connet-dev/connet/selfhosted"
	"github.com/klev-dev/kleverr"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

type Config struct {
	LogLevel  string `toml:"log-level"`
	LogFormat string `toml:"log-format"`

	Server ServerConfig `toml:"server"`
	Client ClientConfig `toml:"client"`

	Control ControlConfig `toml:"control"`
	Relay   RelayConfig   `toml:"relay"`
}

type ServerConfig struct {
	Tokens     []string `toml:"tokens"`
	TokensFile string   `toml:"tokens-file"`

	Addr string `toml:"addr"`
	Cert string `toml:"cert-file"`
	Key  string `toml:"key-file"`

	RelayAddr     string `toml:"relay-addr"`
	RelayHostname string `toml:"relay-hostname"`

	StoreDir string `toml:"store-dir"`
}

type ControlConfig struct {
	ClientTokens     []string `toml:"client-tokens"`
	ClientTokensFile string   `toml:"client-tokens-file"`

	RelayTokens     []string `toml:"relay-tokens"`
	RelayTokensFile string   `toml:"relay-tokens-file"`

	Addr string `toml:"addr"`
	Cert string `toml:"cert-file"`
	Key  string `toml:"key-file"`

	StoreDir string `toml:"store-dir"`
}

type RelayConfig struct {
	Token     string `toml:"token"`
	TokenFile string `toml:"token-file"`

	Addr     string `toml:"addr"`
	Hostname string `toml:"hostname"`

	ControlAddr string `toml:"control-addr"`
	ControlCAs  string `toml:"control-cas"`

	StoreDir string `toml:"store-dir"`
}

type ClientConfig struct {
	Token     string `toml:"token"`
	TokenFile string `toml:"token-file"`

	ServerAddr string `toml:"server-addr"`
	ServerCAs  string `toml:"server-cas"`
	DirectAddr string `toml:"direct-addr"`

	Destinations map[string]ForwardConfig `toml:"destinations"`
	Sources      map[string]ForwardConfig `toml:"sources"`
}

type ForwardConfig struct {
	Addr  string `toml:"addr"`
	Route string `toml:"route"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd().ExecuteContext(ctx); err != nil {
		if cerr := context.Cause(ctx); errors.Is(cerr, context.Canceled) {
			return
		}
		if kerr := kleverr.Get(err); kerr != nil {
			fmt.Fprintln(os.Stderr, kerr.Print())
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "connet",
		Short:         "connet is a reverse proxy/nat traversal tool",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(serverCmd())
	cmd.AddCommand(controlCmd())
	cmd.AddCommand(relayCmd())
	cmd.AddCommand(checkCmd())

	filename := cmd.Flags().String("config", "", "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Client.Token, "token", "", "token to use")
	cmd.Flags().StringVar(&flagsConfig.Client.TokenFile, "token-file", "", "token file to use")

	cmd.Flags().StringVar(&flagsConfig.Client.ServerAddr, "server-addr", "", "control server address to connect")
	cmd.Flags().StringVar(&flagsConfig.Client.ServerCAs, "server-cas", "", "control server CAs to use")
	cmd.Flags().StringVar(&flagsConfig.Client.DirectAddr, "direct-addr", "", "direct server address to listen")

	var dstName string
	var dstCfg ForwardConfig
	cmd.Flags().StringVar(&dstName, "dst-name", "", "destination name")
	cmd.Flags().StringVar(&dstCfg.Addr, "dst-addr", "", "destination address")
	cmd.Flags().StringVar(&dstCfg.Route, "dst-route", "", "destination route")

	var srcName string
	var srcCfg ForwardConfig
	cmd.Flags().StringVar(&srcName, "src-name", "", "source name")
	cmd.Flags().StringVar(&srcCfg.Addr, "src-addr", "", "source address")
	cmd.Flags().StringVar(&srcCfg.Route, "src-route", "", "source route")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(*filename)
		if err != nil {
			return err
		}

		if dstName != "" {
			flagsConfig.Client.Destinations = map[string]ForwardConfig{dstName: dstCfg}
		}
		if srcName != "" {
			flagsConfig.Client.Sources = map[string]ForwardConfig{srcName: srcCfg}
		}

		cfg.merge(flagsConfig)

		logger, err := logger(cfg)
		if err != nil {
			return kleverr.Ret(err)
		}

		return clientRun(cmd.Context(), cfg.Client, logger)
	}

	return cmd
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "run connet server",
	}

	filename := cmd.Flags().String("config", "", "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringArrayVar(&flagsConfig.Server.Tokens, "tokens", nil, "tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Server.TokensFile, "tokens-file", "", "tokens file to load")

	cmd.Flags().StringVar(&flagsConfig.Server.Addr, "addr", "", "control server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Cert, "cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Key, "key-file", "", "control server key to use")

	cmd.Flags().StringVar(&flagsConfig.Server.RelayAddr, "relay-addr", "", "relay server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.RelayHostname, "relay-hostname", "", "relay server public hostname to use")

	cmd.Flags().StringVar(&flagsConfig.Server.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(*filename)
		if err != nil {
			return err
		}

		cfg.merge(flagsConfig)

		logger, err := logger(cfg)
		if err != nil {
			return kleverr.Ret(err)
		}

		return serverRun(cmd.Context(), cfg.Server, logger)
	}

	return cmd
}

func controlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control",
		Short: "run connet control server",
	}

	filename := cmd.Flags().String("config", "", "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringArrayVar(&flagsConfig.Control.ClientTokens, "client-tokens", nil, "client tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Control.ClientTokensFile, "client-tokens-file", "", "client tokens file to load")

	cmd.Flags().StringArrayVar(&flagsConfig.Control.RelayTokens, "relay-tokens", nil, "relay tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Control.RelayTokensFile, "relay-tokens-file", "", "relay tokens file to load")

	cmd.Flags().StringVar(&flagsConfig.Control.Addr, "addr", "", "control server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Control.Cert, "cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Control.Key, "key-file", "", "control server key to use")

	cmd.Flags().StringVar(&flagsConfig.Control.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(*filename)
		if err != nil {
			return err
		}

		cfg.merge(flagsConfig)

		logger, err := logger(cfg)
		if err != nil {
			return kleverr.Ret(err)
		}

		return controlRun(cmd.Context(), cfg.Control, logger)
	}

	return cmd
}

func relayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "run connet relay server",
	}

	filename := cmd.Flags().String("config", "", "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.Token, "token", "", "token to use")
	cmd.Flags().StringVar(&flagsConfig.Relay.TokenFile, "token-file", "", "token file to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.Addr, "addr", "", "server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Relay.Hostname, "hostname", "", "server public hostname to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.ControlAddr, "control-addr", "", "control server address to connect")
	cmd.Flags().StringVar(&flagsConfig.Relay.ControlCAs, "control-cas", "", "control server CAs to use")

	cmd.Flags().StringVar(&flagsConfig.Relay.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(*filename)
		if err != nil {
			return err
		}

		cfg.merge(flagsConfig)

		logger, err := logger(cfg)
		if err != nil {
			return kleverr.Ret(err)
		}

		return relayRun(cmd.Context(), cfg.Relay, logger)
	}

	return cmd
}

func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check <config-file>",
		Short: "check configuration file",
		Args:  cobra.ExactArgs(1),
	}

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(args[0])
		if err != nil {
			return err
		}

		if _, err := logger(cfg); err != nil {
			return kleverr.Ret(err)
		}

		return nil
	}

	return cmd
}

func loadConfig(file string) (Config, error) {
	var cfg Config
	if file == "" {
		return cfg, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return cfg, err
	}
	dec := toml.NewDecoder(f)
	dec = dec.DisallowUnknownFields()
	err = dec.Decode(&cfg)
	return cfg, err
}

func logger(cfg Config) (*slog.Logger, error) {
	logLevel := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	case "info", "":
		logLevel = slog.LevelInfo
	default:
		return nil, kleverr.Newf("'%s' is not a valid log level (one of debug|info|warn|error)", cfg.LogLevel)
	}

	switch cfg.LogFormat {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		})), nil
	case "text", "":
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		})), nil
	default:
		return nil, kleverr.Newf("'%s' is not a valid log format (one of json|text)", cfg.LogFormat)
	}
}

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

	for name, fc := range cfg.Destinations {
		route, err := parseRouteOption(fc.Route)
		if err != nil {
			return err
		}
		opts = append(opts, connet.ClientDestination(name, fc.Addr, route))
	}
	for name, fc := range cfg.Sources {
		route, err := parseRouteOption(fc.Route)
		if err != nil {
			return err
		}
		opts = append(opts, connet.ClientSource(name, fc.Addr, route))
	}

	opts = append(opts, connet.ClientLogger(logger))

	cl, err := connet.NewClient(opts...)
	if err != nil {
		return err
	}
	return cl.Run(ctx)
}

func serverRun(ctx context.Context, cfg ServerConfig, logger *slog.Logger) error {
	var opts []connet.ServerOption

	if cfg.TokensFile != "" {
		tokens, err := loadTokens(cfg.TokensFile)
		if err != nil {
			return err
		}
		opts = append(opts, connet.ServerClientTokens(tokens...))
	} else {
		opts = append(opts, connet.ServerClientTokens(cfg.Tokens...))
	}

	if cfg.Addr != "" {
		opts = append(opts, connet.ServerControlAddress(cfg.Addr))
	}
	if cfg.Cert != "" {
		opts = append(opts, connet.ServerControlCertificate(cfg.Cert, cfg.Key))
	}

	if cfg.RelayAddr != "" {
		opts = append(opts, connet.ServerRelayAddress(cfg.RelayAddr))
	}
	if cfg.RelayHostname != "" {
		opts = append(opts, connet.ServerRelayHostname(cfg.RelayHostname))
	}

	if cfg.StoreDir != "" {
		opts = append(opts, connet.ServerStoreDir(cfg.StoreDir))
	}

	opts = append(opts, connet.ServerLogger(logger))

	srv, err := connet.NewServer(opts...)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func controlRun(ctx context.Context, cfg ControlConfig, logger *slog.Logger) error {
	controlCfg := control.Config{
		Logger: logger,
	}

	if cfg.ClientTokensFile != "" {
		tokens, err := loadTokens(cfg.ClientTokensFile)
		if err != nil {
			return err
		}
		controlCfg.ClientAuth = selfhosted.NewClientAuthenticator(tokens...)
	} else {
		controlCfg.ClientAuth = selfhosted.NewClientAuthenticator(cfg.ClientTokens...)
	}

	if cfg.RelayTokensFile != "" {
		tokens, err := loadTokens(cfg.RelayTokensFile)
		if err != nil {
			return err
		}
		controlCfg.RelayAuth = selfhosted.NewRelayAuthenticator(tokens...)
	} else {
		controlCfg.RelayAuth = selfhosted.NewRelayAuthenticator(cfg.RelayTokens...)
	}

	if cfg.Addr == "" {
		cfg.Addr = ":19190"
	}
	addr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return kleverr.Newf("control address cannot be resolved: %w", err)
	}
	controlCfg.Addr = addr

	if cfg.Cert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return kleverr.Newf("control cert cannot be loaded: %w", err)
		}
		controlCfg.Cert = cert
	}

	if cfg.StoreDir == "" {
		controlCfg.Stores, err = control.NewTmpFileStores()
		if err != nil {
			return err
		}
	} else {
		controlCfg.Stores = control.NewFileStores(cfg.StoreDir)
	}

	srv, err := control.NewServer(controlCfg)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
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

	if cfg.Addr == "" {
		cfg.Addr = ":19191"
		if cfg.Hostname == "" {
			cfg.Hostname = "localhost"
		}
	}
	serverAddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return kleverr.Newf("server address cannot be resolved: %w", err)
	}
	relayCfg.Addr = serverAddr

	relayCfg.Hostport = model.HostPort{Host: cfg.Hostname, Port: uint16(serverAddr.Port)}

	if cfg.ControlAddr == "" {
		cfg.ControlAddr = "localhost:19190"
	}
	controlAddr, err := net.ResolveUDPAddr("udp", cfg.ControlAddr)
	if err != nil {
		return kleverr.Newf("control address cannot be resolved: %w", err)
	}
	relayCfg.ControlAddr = controlAddr

	if cfg.ControlCAs != "" {
		casData, err := os.ReadFile(cfg.ControlCAs)
		if err != nil {
			return kleverr.Newf("cannot read certs file: %w", err)
		}

		cas := x509.NewCertPool()
		if !cas.AppendCertsFromPEM(casData) {
			return kleverr.Newf("no certificates found in %s", cfg.ControlCAs)
		}
		relayCfg.ControlCAs = cas
	}

	controlHost, _, err := net.SplitHostPort(cfg.ControlAddr)
	if err != nil {
		return err
	}
	relayCfg.ControlHost = controlHost

	if cfg.StoreDir == "" {
		relayCfg.Stores, err = relay.NewTmpFileStores()
		if err != nil {
			return err
		}
	} else {
		relayCfg.Stores = relay.NewFileStores(cfg.StoreDir)
	}

	srv, err := relay.NewServer(relayCfg)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func loadTokens(tokensFile string) ([]string, error) {
	f, err := os.Open(tokensFile)
	if err != nil {
		return nil, kleverr.Newf("cannot open tokens file: %w", err)
	}

	var tokens []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		tokens = append(tokens, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, kleverr.Newf("cannot read tokens file: %w", err)
	}
	return tokens, nil
}

func parseRouteOption(s string) (model.RouteOption, error) {
	if s == "" {
		return model.RouteAny, nil
	}
	return model.ParseRouteOption(s)
}

func (c *Config) merge(o Config) {
	c.LogLevel = override(c.LogLevel, o.LogLevel)
	c.LogFormat = override(c.LogFormat, o.LogFormat)

	c.Server.merge(o.Server)
	c.Client.merge(o.Client)

	c.Control.merge(o.Control)
	c.Relay.merge(o.Relay)
}

func (c *ClientConfig) merge(o ClientConfig) {
	c.Token = override(c.Token, o.Token)
	c.TokenFile = override(c.TokenFile, o.TokenFile)

	c.ServerAddr = override(c.ServerAddr, o.ServerAddr)
	c.ServerCAs = override(c.ServerCAs, o.ServerCAs)
	c.DirectAddr = override(c.DirectAddr, o.DirectAddr)

	for k, v := range o.Destinations {
		if c.Destinations == nil {
			c.Destinations = map[string]ForwardConfig{}
		}
		c.Destinations[k] = mergeForwardConfig(c.Destinations[k], v)
	}

	for k, v := range o.Sources {
		if c.Sources == nil {
			c.Sources = map[string]ForwardConfig{}
		}
		c.Sources[k] = mergeForwardConfig(c.Sources[k], v)
	}
}

func (c *ServerConfig) merge(o ServerConfig) {
	c.Tokens = append(c.Tokens, o.Tokens...)
	c.TokensFile = override(c.TokensFile, o.TokensFile)

	c.Addr = override(c.Addr, o.Addr)
	c.Cert = override(c.Cert, o.Cert)
	c.Key = override(c.Key, o.Key)

	c.RelayAddr = override(c.RelayAddr, o.RelayAddr)
	c.RelayHostname = override(c.RelayHostname, o.RelayHostname)

	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func (c *ControlConfig) merge(o ControlConfig) {
	c.ClientTokens = append(c.ClientTokens, o.ClientTokens...)
	c.ClientTokensFile = override(c.ClientTokensFile, o.ClientTokensFile)

	c.RelayTokens = append(c.RelayTokens, o.RelayTokens...)
	c.RelayTokensFile = override(c.RelayTokensFile, o.RelayTokensFile)

	c.Addr = override(c.Addr, o.Addr)
	c.Cert = override(c.Cert, o.Cert)
	c.Key = override(c.Key, o.Key)

	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func (c *RelayConfig) merge(o RelayConfig) {
	c.Token = override(c.Token, o.Token)
	c.TokenFile = override(c.TokenFile, o.TokenFile)

	c.Addr = override(c.Addr, o.Addr)
	c.Hostname = override(c.Hostname, o.Hostname)

	c.ControlAddr = override(c.ControlAddr, o.ControlAddr)
	c.ControlCAs = override(c.ControlCAs, o.ControlCAs)

	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func mergeForwardConfig(c, o ForwardConfig) ForwardConfig {
	return ForwardConfig{
		Addr:  override(c.Addr, o.Addr),
		Route: override(c.Route, o.Route),
	}
}

func override(s, o string) string {
	if o != "" {
		return o
	}
	return s
}

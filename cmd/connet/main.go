package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/keihaya-com/connet"
	"github.com/keihaya-com/connet/model"
	"github.com/klev-dev/kleverr"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

type Config struct {
	LogLevel  string       `toml:"log_level"`
	LogFormat string       `toml:"log_format"`
	Server    ServerConfig `toml:"server"`
	Client    ClientConfig `toml:"client"`
}

type ServerConfig struct {
	Tokens     []string `toml:"tokens"`
	TokensFile string   `toml:"tokens_file"`

	Hostname string `toml:"hostname"`
	Cert     string `toml:"cert_file"`
	Key      string `toml:"key_file"`

	Control ListenerConfig `toml:"control"`
	Relay   ListenerConfig `toml:"relay"`
}

type ListenerConfig struct {
	Addr string `toml:"bind_addr"`
	Cert string `toml:"cert_file"`
	Key  string `toml:"key_file"`
}

type ClientConfig struct {
	Token     string `toml:"token"`
	TokenFile string `toml:"token_file"`

	ServerAddr string `toml:"server_addr"`
	ServerCAs  string `toml:"server_cas"`
	DirectAddr string `toml:"direct_addr"`

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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connet",
		Short: "connet is a reverse proxy/nat traversal tool",
	}

	cmd.AddCommand(serverCmd())
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

		return client(cmd.Context(), cfg.Client, logger)
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

	cmd.Flags().StringVar(&flagsConfig.Server.Hostname, "hostname", "", "hostname to connect to")
	cmd.Flags().StringVar(&flagsConfig.Server.Cert, "cert-file", "", "server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Key, "key-file", "", "server key to use")

	cmd.Flags().StringVar(&flagsConfig.Server.Control.Addr, "control-addr", "", "control server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Control.Cert, "control-cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Control.Key, "control-key-file", "", "control server key to use")

	cmd.Flags().StringVar(&flagsConfig.Server.Relay.Addr, "relay-addr", "", "relay server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Relay.Cert, "relay-cert-file", "", "relay server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Relay.Key, "relay-key-file", "", "relay server key to use")

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

		return server(cmd.Context(), cfg.Server, logger)
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

func server(ctx context.Context, cfg ServerConfig, logger *slog.Logger) error {
	var opts []connet.ServerOption

	if cfg.TokensFile != "" {
		tokens, err := loadTokens(cfg.TokensFile)
		if err != nil {
			return err
		}
		opts = append(opts, connet.ServerTokens(tokens...))
	} else {
		opts = append(opts, connet.ServerTokens(cfg.Tokens...))
	}

	if cfg.Hostname != "" {
		opts = append(opts, connet.ServerHostname(cfg.Hostname))
	}
	if cfg.Cert != "" {
		opts = append(opts, connet.ServerDefaultCertificate(cfg.Cert, cfg.Key))
	}

	if cfg.Control.Addr != "" {
		opts = append(opts, connet.ServerControlAddress(cfg.Control.Addr))
	}
	if cfg.Control.Cert != "" {
		opts = append(opts, connet.ServerControlCertificate(cfg.Control.Cert, cfg.Control.Key))
	}

	if cfg.Relay.Addr != "" {
		opts = append(opts, connet.ServerRelayAddress(cfg.Relay.Addr))
	}
	if cfg.Relay.Cert != "" {
		opts = append(opts, connet.ServerRelayCertificate(cfg.Relay.Cert, cfg.Relay.Key))
	}

	opts = append(opts, connet.ServerLogger(logger))

	srv, err := connet.NewServer(opts...)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func client(ctx context.Context, cfg ClientConfig, logger *slog.Logger) error {
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
}

func (c *ServerConfig) merge(o ServerConfig) {
	c.Tokens = append(c.Tokens, o.Tokens...)
	c.TokensFile = override(c.TokensFile, o.TokensFile)

	c.Hostname = override(c.Hostname, o.Hostname)
	c.Cert = override(c.Cert, o.Cert)
	c.Key = override(c.Key, o.Key)

	c.Control.Addr = override(c.Control.Addr, o.Control.Addr)
	c.Control.Cert = override(c.Control.Cert, o.Control.Cert)
	c.Control.Key = override(c.Control.Key, o.Control.Key)

	c.Relay.Addr = override(c.Relay.Addr, o.Relay.Addr)
	c.Relay.Cert = override(c.Relay.Cert, o.Relay.Cert)
	c.Relay.Key = override(c.Relay.Key, o.Relay.Key)
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

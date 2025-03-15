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
	"strings"
	"syscall"

	"github.com/connet-dev/connet"
	"github.com/connet-dev/connet/client"
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/relay"
	"github.com/connet-dev/connet/restr"
	"github.com/connet-dev/connet/selfhosted"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	LogLevel  string `toml:"log-level"`
	LogFormat string `toml:"log-format"`

	Client ClientConfig `toml:"client"`
	Server ServerConfig `toml:"server"`

	Control ControlConfig `toml:"control"`
	Relay   RelayConfig   `toml:"relay"`
}

type ClientConfig struct {
	Token     string `toml:"token"`
	TokenFile string `toml:"token-file"`

	ServerAddr string `toml:"server-addr"`
	ServerCAs  string `toml:"server-cas"`

	DirectAddr string `toml:"direct-addr"`
	StatusAddr string `toml:"status-addr"`

	Destinations map[string]DestinationConfig `toml:"destinations"`
	Sources      map[string]SourceConfig      `toml:"sources"`
}

type DestinationConfig struct {
	Addr              string `toml:"addr"`
	Route             string `toml:"route"`
	ProxyProtoVersion string `toml:"proxy-proto-version"`
	FileServerRoot    string `toml:"file-server-root"`
}

type SourceConfig struct {
	Addr  string `toml:"addr"`
	Route string `toml:"route"`
}

type ServerConfig struct {
	Cert string `toml:"cert-file"`
	Key  string `toml:"key-file"`

	Addr              string             `toml:"addr"`
	IPRestriction     IPRestriction      `toml:"ip-restriction"`
	Tokens            []string           `toml:"tokens"`
	TokensFile        string             `toml:"tokens-file"`
	TokenRestrictions []TokenRestriction `toml:"token-restriction"`

	RelayAddr     string `toml:"relay-addr"`
	RelayHostname string `toml:"relay-hostname"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

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

type RelayConfig struct {
	Token     string `toml:"token"`
	TokenFile string `toml:"token-file"`

	Addr     string `toml:"addr"`
	Hostname string `toml:"hostname"`

	ControlAddr string `toml:"control-addr"`
	ControlCAs  string `toml:"control-cas"`

	StatusAddr string `toml:"status-addr"`
	StoreDir   string `toml:"store-dir"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd().ExecuteContext(ctx); err != nil {
		if cerr := context.Cause(ctx); errors.Is(cerr, context.Canceled) {
			return
		}
		printError(err, 0)
		os.Exit(1)
	}
}

func printError(err error, level int) {
	errStr := err.Error()

	nextErr := errors.Unwrap(err)
	if nextErr != nil {
		errStr = strings.TrimSuffix(errStr, nextErr.Error())
		errStr = strings.TrimSuffix(errStr, ": ")
	}

	fmt.Fprintf(os.Stderr, "error: %s%s\n", strings.Repeat(" ", level*2), errStr)
	if nextErr != nil {
		printError(nextErr, level+1)
	}
}

type cobraRunE = func(cmd *cobra.Command, args []string) error

func wrapErr(ws string, runErr cobraRunE) cobraRunE {
	return func(cmd *cobra.Command, args []string) error {
		if err := runErr(cmd, args); err != nil {
			return fmt.Errorf("%s: %w", ws, err)
		}
		return nil
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
	cmd.Flags().StringVar(&flagsConfig.Client.StatusAddr, "status-addr", "", "status server address to listen")

	var dstName string
	var dstCfg DestinationConfig
	cmd.Flags().StringVar(&dstName, "dst-name", "", "destination name")
	cmd.Flags().StringVar(&dstCfg.Addr, "dst-addr", "", "destination address")
	cmd.Flags().StringVar(&dstCfg.FileServerRoot, "dst-file-server-root", "", "destination file server root directory")
	cmd.Flags().StringVar(&dstCfg.Route, "dst-route", "", "destination route")

	var srcName string
	var srcCfg SourceConfig
	cmd.Flags().StringVar(&srcName, "src-name", "", "source name")
	cmd.Flags().StringVar(&srcCfg.Addr, "src-addr", "", "source address")
	cmd.Flags().StringVar(&srcCfg.Route, "src-route", "", "source route")

	cmd.RunE = wrapErr("run connet client", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig(*filename)
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

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "run connet server",
	}

	filename := cmd.Flags().String("config", "", "config file to load")

	var flagsConfig Config
	cmd.Flags().StringVar(&flagsConfig.LogLevel, "log-level", "", "log level to use")
	cmd.Flags().StringVar(&flagsConfig.LogFormat, "log-format", "", "log formatter to use")

	cmd.Flags().StringVar(&flagsConfig.Server.Addr, "addr", "", "control server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Cert, "cert-file", "", "control server cert to use")
	cmd.Flags().StringVar(&flagsConfig.Server.Key, "key-file", "", "control server key to use")

	cmd.Flags().StringArrayVar(&flagsConfig.Server.Tokens, "tokens", nil, "tokens for clients to connect")
	cmd.Flags().StringVar(&flagsConfig.Server.TokensFile, "tokens-file", "", "tokens file to load")
	cmd.Flags().StringSliceVar(&flagsConfig.Server.IPRestriction.AllowCIDRs, "tokens-allow-cidr", nil, "cidr to allow client connections from")
	cmd.Flags().StringSliceVar(&flagsConfig.Server.IPRestriction.DenyCIDRs, "tokens-deny-cidr", nil, "cidr to deny client connections from")

	cmd.Flags().StringVar(&flagsConfig.Server.RelayAddr, "relay-addr", "", "relay server addr to use")
	cmd.Flags().StringVar(&flagsConfig.Server.RelayHostname, "relay-hostname", "", "relay server public hostname to use")

	cmd.Flags().StringVar(&flagsConfig.Server.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Server.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig(*filename)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
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

func controlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control",
		Short: "run connet control server",
	}

	filename := cmd.Flags().String("config", "", "config file to load")

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
		cfg, err := loadConfig(*filename)
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

	cmd.Flags().StringVar(&flagsConfig.Relay.StatusAddr, "status-addr", "", "status server address to listen")
	cmd.Flags().StringVar(&flagsConfig.Relay.StoreDir, "store-dir", "", "storage dir, /tmp subdirectory if empty")

	cmd.RunE = wrapErr("run connet relay server", func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig(*filename)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
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

func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check <config-file>",
		Short: "check configuration file",
		Args:  cobra.ExactArgs(1),
	}

	cmd.RunE = func(_ *cobra.Command, args []string) error {
		cfg, err := loadConfig(args[0])
		if err != nil {
			return err
		}

		if _, err := logger(cfg); err != nil {
			return err
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
	if err != nil {
		var serr *toml.StrictMissingError
		var derr *toml.DecodeError
		if errors.As(err, &serr) {
			fmt.Println(serr.String())
		} else if errors.As(err, &derr) {
			fmt.Println(derr.String())
		}
	}
	return cfg, err
}

func logger(cfg Config) (*slog.Logger, error) {
	var logLevel slog.Level
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
		return nil, fmt.Errorf("invalid level '%s' (debug|info|warn|error)", cfg.LogLevel)
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
		return nil, fmt.Errorf("invalid format '%s' (json|text)", cfg.LogFormat)
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

	if cfg.StatusAddr != "" {
		opts = append(opts, connet.ClientStatusAddress(cfg.StatusAddr))
	}

	var srvs []*netc.FileServer
	for name, fc := range cfg.Destinations {
		route, err := parseRouteOption(fc.Route)
		if err != nil {
			return err
		}
		proxy, err := parseProxyVersion(fc.ProxyProtoVersion)
		if err != nil {
			return err
		}
		if fc.FileServerRoot != "" {
			srvs = append(srvs, &netc.FileServer{Addr: fc.Addr, Root: fc.FileServerRoot})
		}
		opts = append(opts, connet.ClientDestination(
			client.NewDestinationConfig(name, fc.Addr).WithRoute(route).WithProxy(proxy)))
	}

	for name, fc := range cfg.Sources {
		route, err := parseRouteOption(fc.Route)
		if err != nil {
			return err
		}
		opts = append(opts, connet.ClientSource(
			client.NewSourceConfig(name, fc.Addr).WithRoute(route)))
	}

	opts = append(opts, connet.ClientLogger(logger))

	cl, err := connet.NewClient(opts...)
	if err != nil {
		return fmt.Errorf("client create: %w", err)
	}
	if len(srvs) > 0 {
		g, ctx := errgroup.WithContext(ctx)
		for _, srv := range srvs {
			g.Go(func() error { return srv.Run(ctx) })
		}

		g.Go(func() error { return cl.Run(ctx) })
		return g.Wait()
	}
	return cl.Run(ctx)
}

func serverRun(ctx context.Context, cfg ServerConfig, logger *slog.Logger) error {
	var opts []connet.ServerOption

	if cfg.Addr != "" {
		opts = append(opts, connet.ServerClientsAddress(cfg.Addr))
	}
	if cfg.Cert != "" {
		opts = append(opts, connet.ServerCertificate(cfg.Cert, cfg.Key))
	}

	if len(cfg.IPRestriction.AllowCIDRs) > 0 || len(cfg.IPRestriction.DenyCIDRs) > 0 {
		opts = append(opts, connet.ServerClientRestrictions(cfg.IPRestriction.AllowCIDRs, cfg.IPRestriction.DenyCIDRs))
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
	opts = append(opts, connet.ServerClientAuthenticator(clientAuth))

	if cfg.RelayAddr != "" {
		opts = append(opts, connet.ServerRelayAddress(cfg.RelayAddr))
	}
	if cfg.RelayHostname != "" {
		opts = append(opts, connet.ServerRelayHostname(cfg.RelayHostname))
	}

	if cfg.StatusAddr != "" {
		opts = append(opts, connet.ServerStatusAddress(cfg.StatusAddr))
	}
	if cfg.StoreDir != "" {
		opts = append(opts, connet.ServerStoreDir(cfg.StoreDir))
	}

	opts = append(opts, connet.ServerLogger(logger))

	srv, err := connet.NewServer(opts...)
	if err != nil {
		return fmt.Errorf("cannot create server: %w", err)
	}
	return srv.Run(ctx)
}

func controlRun(ctx context.Context, cfg ControlConfig, logger *slog.Logger) error {
	controlCfg := control.Config{
		Logger: logger,
	}

	if cfg.Cert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return fmt.Errorf("control cert: %w", err)
		}
		controlCfg.Cert = cert
	}

	if cfg.ClientsAddr == "" {
		cfg.ClientsAddr = ":19190"
	}
	clientAddr, err := net.ResolveUDPAddr("udp", cfg.ClientsAddr)
	if err != nil {
		return fmt.Errorf("control client address: %w", err)
	}
	controlCfg.ClientsAddr = clientAddr

	if len(cfg.ClientsIPRestriction.AllowCIDRs) > 0 || len(cfg.ClientsIPRestriction.DenyCIDRs) > 0 {
		iprestr, err := restr.ParseIP(cfg.ClientsIPRestriction.AllowCIDRs, cfg.ClientsIPRestriction.DenyCIDRs)
		if err != nil {
			return err
		}
		controlCfg.ClientsRestr = iprestr
	}

	clientTokens := cfg.ClientsTokens
	if cfg.ClientsTokensFile != "" {
		clientTokens, err = loadTokens(cfg.ClientsTokensFile)
		if err != nil {
			return err
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
		return fmt.Errorf("control relay address: %w", err)
	}
	controlCfg.RelaysAddr = relayAddr

	if len(cfg.RelaysIPRestriction.AllowCIDRs) > 0 || len(cfg.RelaysIPRestriction.DenyCIDRs) > 0 {
		iprestr, err := restr.ParseIP(cfg.RelaysIPRestriction.AllowCIDRs, cfg.RelaysIPRestriction.DenyCIDRs)
		if err != nil {
			return err
		}
		controlCfg.RelaysRestr = iprestr
	}

	relayTokens := cfg.RelaysTokens
	if cfg.RelaysTokensFile != "" {
		relayTokens, err = loadTokens(cfg.RelaysTokensFile)
		if err != nil {
			return err
		}
	}
	controlCfg.RelaysAuth, err = parseRelayAuth(relayTokens, cfg.RelaysTokenIPRestrictions)
	if err != nil {
		return err
	}

	if cfg.StatusAddr != "" {
		statusAddr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("control status address: %w", err)
		}
		controlCfg.StatusAddr = statusAddr
	}

	if cfg.StoreDir == "" {
		dir, err := os.MkdirTemp("", "connet-control-")
		if err != nil {
			return err
		}
		logger.Info("using temporary store directory", "dir", dir)
		cfg.StoreDir = dir
	}
	controlCfg.Stores = control.NewFileStores(cfg.StoreDir)

	srv, err := control.NewServer(controlCfg)
	if err != nil {
		return fmt.Errorf("control server create: %w", err)
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
		return fmt.Errorf("relay server address: %w", err)
	}
	relayCfg.Addr = serverAddr

	relayCfg.Hostport = model.HostPort{Host: cfg.Hostname, Port: uint16(serverAddr.Port)}

	if cfg.ControlAddr == "" {
		cfg.ControlAddr = "localhost:19189"
	}
	controlAddr, err := net.ResolveUDPAddr("udp", cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("relay control address: %w", err)
	}
	relayCfg.ControlAddr = controlAddr

	if cfg.ControlCAs != "" {
		casData, err := os.ReadFile(cfg.ControlCAs)
		if err != nil {
			return fmt.Errorf("relay control cert file: %w", err)
		}

		cas := x509.NewCertPool()
		if !cas.AppendCertsFromPEM(casData) {
			return fmt.Errorf("relay no certificates found in %s", cfg.ControlCAs)
		}
		relayCfg.ControlCAs = cas
	}

	controlHost, _, err := net.SplitHostPort(cfg.ControlAddr)
	if err != nil {
		return err
	}
	relayCfg.ControlHost = controlHost

	if cfg.StatusAddr != "" {
		statusAddr, err := net.ResolveTCPAddr("tcp", cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("relay status address cannot: %w", err)
		}
		relayCfg.StatusAddr = statusAddr
	}

	if cfg.StoreDir == "" {
		dir, err := os.MkdirTemp("", "connet-relay-")
		if err != nil {
			return err
		}
		logger.Info("using temporary store directory", "dir", dir)
		cfg.StoreDir = dir
	}
	relayCfg.Stores = relay.NewFileStores(cfg.StoreDir)

	srv, err := relay.NewServer(relayCfg)
	if err != nil {
		return fmt.Errorf("relay server create: %w", err)
	}
	return srv.Run(ctx)
}

func loadTokens(tokensFile string) ([]string, error) {
	f, err := os.Open(tokensFile)
	if err != nil {
		return nil, fmt.Errorf("open tokens file: %w", err)
	}

	var tokens []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		tokens = append(tokens, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read tokens file: %w", err)
	}
	return tokens, nil
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
	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)

	for k, v := range o.Destinations {
		if c.Destinations == nil {
			c.Destinations = map[string]DestinationConfig{}
		}
		c.Destinations[k] = mergeDestinationConfig(c.Destinations[k], v)
	}

	for k, v := range o.Sources {
		if c.Sources == nil {
			c.Sources = map[string]SourceConfig{}
		}
		c.Sources[k] = mergeSourceConfig(c.Sources[k], v)
	}
}

func (c *ServerConfig) merge(o ServerConfig) {
	c.Addr = override(c.Addr, o.Addr)
	c.Cert = override(c.Cert, o.Cert)
	c.Key = override(c.Key, o.Key)

	c.IPRestriction.AllowCIDRs = append(c.IPRestriction.AllowCIDRs, o.IPRestriction.AllowCIDRs...)
	c.IPRestriction.DenyCIDRs = append(c.IPRestriction.DenyCIDRs, o.IPRestriction.DenyCIDRs...)
	c.Tokens = append(c.Tokens, o.Tokens...)
	c.TokensFile = override(c.TokensFile, o.TokensFile)

	c.RelayAddr = override(c.RelayAddr, o.RelayAddr)
	c.RelayHostname = override(c.RelayHostname, o.RelayHostname)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func (c *ControlConfig) merge(o ControlConfig) {
	c.Cert = override(c.Cert, o.Cert)
	c.Key = override(c.Key, o.Key)

	c.ClientsAddr = override(c.ClientsAddr, o.ClientsAddr)
	c.ClientsIPRestriction.AllowCIDRs = append(c.ClientsIPRestriction.AllowCIDRs, o.ClientsIPRestriction.AllowCIDRs...)
	c.ClientsIPRestriction.DenyCIDRs = append(c.ClientsIPRestriction.DenyCIDRs, o.ClientsIPRestriction.DenyCIDRs...)
	c.ClientsTokens = append(c.ClientsTokens, o.ClientsTokens...)
	c.ClientsTokensFile = override(c.ClientsTokensFile, o.ClientsTokensFile)

	c.RelaysAddr = override(c.RelaysAddr, o.RelaysAddr)
	c.RelaysIPRestriction.AllowCIDRs = append(c.RelaysIPRestriction.AllowCIDRs, o.RelaysIPRestriction.AllowCIDRs...)
	c.RelaysIPRestriction.DenyCIDRs = append(c.RelaysIPRestriction.DenyCIDRs, o.RelaysIPRestriction.DenyCIDRs...)
	c.RelaysTokens = append(c.RelaysTokens, o.RelaysTokens...)
	c.RelaysTokensFile = override(c.RelaysTokensFile, o.RelaysTokensFile)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func (c *RelayConfig) merge(o RelayConfig) {
	c.Token = override(c.Token, o.Token)
	c.TokenFile = override(c.TokenFile, o.TokenFile)

	c.Addr = override(c.Addr, o.Addr)
	c.Hostname = override(c.Hostname, o.Hostname)

	c.ControlAddr = override(c.ControlAddr, o.ControlAddr)
	c.ControlCAs = override(c.ControlCAs, o.ControlCAs)

	c.StatusAddr = override(c.StatusAddr, o.StatusAddr)
	c.StoreDir = override(c.StoreDir, o.StoreDir)
}

func mergeDestinationConfig(c, o DestinationConfig) DestinationConfig {
	return DestinationConfig{
		Addr:           override(c.Addr, o.Addr),
		FileServerRoot: override(c.FileServerRoot, o.FileServerRoot),
		Route:          override(c.Route, o.Route),
	}
}

func mergeSourceConfig(c, o SourceConfig) SourceConfig {
	return SourceConfig{
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

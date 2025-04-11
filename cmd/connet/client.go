package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/connet-dev/connet"
	"github.com/connet-dev/connet/model"
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

	RelayEncryptions []string                     `toml:"relay-encryptions"`
	Destinations     map[string]DestinationConfig `toml:"destinations"`
	Sources          map[string]SourceConfig      `toml:"sources"`
}

type DestinationConfig struct {
	Route             string   `toml:"route"`
	RelayEncryptions  []string `toml:"relay-encryptions"`
	ProxyProtoVersion string   `toml:"proxy-proto-version"`

	TCP  TCPConfig             `toml:"tcp"`
	TLS  DestinationTLSConfig  `toml:"tls"`
	HTTP DestinationHTTPConfig `toml:"http"`
}

type DestinationTLSConfig struct {
	TCPConfig
	CAsFile string `toml:"cas-file"`
}

type DestinationHTTPConfig struct {
	StaticServerRoot string `toml:"static-server-root"`
}

type SourceConfig struct {
	Route            string   `toml:"route"`
	RelayEncryptions []string `toml:"relay-encryptions"`

	TCP TCPConfig       `toml:"tcp"`
	TLS SourceTLSConfig `toml:"tls"`
}

type SourceTLSConfig struct {
	TCPConfig
	CertFile string `toml:"cert-file"`
	KeyFile  string `toml:"key-file"`
}

type TCPConfig struct {
	Addr string `toml:"addr"`
}

func clientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "connet",
		Short:         "connet is a reverse proxy/nat traversal tool",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

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

	var dstName string
	var dstCfg DestinationConfig
	cmd.Flags().StringVar(&dstName, "dst-name", "", "destination name")
	cmd.Flags().StringVar(&dstCfg.Route, "dst-route", "", "destination route")
	cmd.Flags().StringVar(&dstCfg.TCP.Addr, "dst-tcp-addr", "", "destination tcp address")
	cmd.Flags().StringVar(&dstCfg.TLS.Addr, "dst-tls-addr", "", "destination tls address")
	cmd.Flags().StringVar(&dstCfg.TLS.CAsFile, "dst-tls-cas-file", "", "destination tls certificate authorities file")
	cmd.Flags().StringVar(&dstCfg.HTTP.StaticServerRoot, "dst-http-static-server-root", "", "destination http static server root")

	var srcName string
	var srcCfg SourceConfig
	cmd.Flags().StringVar(&srcName, "src-name", "", "source name")
	cmd.Flags().StringVar(&srcCfg.Route, "src-route", "", "source route")
	cmd.Flags().StringVar(&srcCfg.TCP.Addr, "src-tcp-addr", "", "source tcp address")
	cmd.Flags().StringVar(&srcCfg.TLS.Addr, "src-tls-addr", "", "source tls address")
	cmd.Flags().StringVar(&srcCfg.TLS.CertFile, "src-tls-cert-file", "", "source tls cert file")
	cmd.Flags().StringVar(&srcCfg.TLS.KeyFile, "src-tls-key-file", "", "source tls key file")

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

	var defaultRelayEncryptions = []model.EncryptionScheme{model.NoEncryption}
	if len(cfg.RelayEncryptions) > 0 {
		res, err := parseEncryptionSchemes(cfg.RelayEncryptions)
		if err != nil {
			return fmt.Errorf("parse relay encryptions: %w", err)
		}
		defaultRelayEncryptions = res
	}

	destinations := map[string]connet.DestinationConfig{}
	destinationHandlers := map[string]newrunnable[connet.Destination]{}
	for name, fc := range cfg.Destinations {
		route, err := parseRouteOption(fc.Route)
		if err != nil {
			return fmt.Errorf("parse route option for destination '%s': %w", name, err)
		}
		proxy, err := parseProxyVersion(fc.ProxyProtoVersion)
		if err != nil {
			return fmt.Errorf("parse proxy proto version for destination '%s': %w", name, err)
		}
		relayEncryptions := defaultRelayEncryptions
		if len(fc.RelayEncryptions) > 0 {
			res, err := parseEncryptionSchemes(fc.RelayEncryptions)
			if err != nil {
				return fmt.Errorf("parse relay encryptions for destination '%s': %w", name, err)
			}
			relayEncryptions = res
		}
		destinations[name] = connet.NewDestinationConfig(name).
			WithRoute(route).
			WithProxy(proxy).
			WithRelayEncryptions(relayEncryptions...)

		switch {
		case fc.TCP.Addr != "" && fc.TLS.Addr != "" && fc.HTTP.StaticServerRoot != "":
			return fmt.Errorf("only one of 'tcp.addr', 'tls.addr' or 'http.static-server-root' needs to be set for destination '%s'", name)
		case fc.TCP.Addr == "" && fc.TLS.Addr == "" && fc.HTTP.StaticServerRoot == "":
			return fmt.Errorf("one of 'tcp.addr', 'tls.addr' or 'http.static-server-root' needs to be set for destination '%s'", name)
		}

		var destCAs *x509.CertPool
		if fc.TLS.CAsFile != "" {
			casData, err := os.ReadFile(fc.TLS.CAsFile)
			if err != nil {
				return fmt.Errorf("read server CAs: %w", err)
			}

			cas := x509.NewCertPool()
			if !cas.AppendCertsFromPEM(casData) {
				return fmt.Errorf("missing server CA certificate in %s", fc.TLS.CAsFile)
			}
			destCAs = cas
		}

		destinationHandlers[name] = func(dst connet.Destination) runnable {
			switch {
			case fc.HTTP.StaticServerRoot != "":
				return connet.NewHTTPFileDestination(dst, fc.HTTP.StaticServerRoot)
			case fc.TLS.Addr != "":
				return connet.NewTLSDestination(dst, fc.TLS.Addr, &tls.Config{RootCAs: destCAs}, logger)
			}
			return connet.NewTCPDestination(dst, fc.TCP.Addr, logger)
		}
	}

	sources := map[string]connet.SourceConfig{}
	sourceHandlers := map[string]newrunnable[connet.Source]{}
	for name, fc := range cfg.Sources {
		route, err := parseRouteOption(fc.Route)
		if err != nil {
			return fmt.Errorf("parse route option for source '%s': %w", name, err)
		}
		relayEncryptions := defaultRelayEncryptions
		if len(fc.RelayEncryptions) > 0 {
			res, err := parseEncryptionSchemes(fc.RelayEncryptions)
			if err != nil {
				return fmt.Errorf("parse relay encryptions for source '%s': %w", name, err)
			}
			relayEncryptions = res
		}
		sources[name] = connet.NewSourceConfig(name).
			WithRoute(route).
			WithRelayEncryptions(relayEncryptions...)

		switch {
		case fc.TLS.Addr != "" && fc.TCP.Addr != "":
			return fmt.Errorf("only one of 'tls.addr' or 'tcp.addr' needs to be set for source '%s'", name)
		case fc.TLS.Addr == "" && fc.TCP.Addr == "":
			return fmt.Errorf("one of 'tls.addr' or 'tcp.addr' needs to be set for source '%s'", name)
		case fc.TLS.Addr != "" && fc.TLS.CertFile == "":
			return fmt.Errorf("'tls.cert-file' is missing for source '%s'", name)
		case fc.TLS.Addr != "" && fc.TLS.KeyFile == "":
			return fmt.Errorf("'tls.key-file' is missing for source '%s'", name)
		}

		var certs []tls.Certificate
		if fc.TLS.Addr != "" {
			cert, err := tls.LoadX509KeyPair(fc.TLS.CertFile, fc.TLS.KeyFile)
			if err != nil {
				return fmt.Errorf("load server cert for source '%s': %w", name, err)
			}
			certs = append(certs, cert)
		}

		sourceHandlers[name] = func(src connet.Source) runnable {
			if fc.TLS.Addr != "" {
				return connet.NewTLSSource(src, fc.TLS.Addr, &tls.Config{Certificates: certs}, logger)
			}
			return connet.NewTCPSource(src, fc.TCP.Addr, logger)
		}
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
			return statusc.Run(ctx, statusAddr.String(), cl.Status)
		})
	}

	for name, cfg := range destinations {
		dst, err := cl.Destination(ctx, cfg)
		if err != nil {
			return err
		}
		if dstrun := destinationHandlers[name]; dstrun != nil {
			g.Go(func() error { return dstrun(dst).Run(ctx) })
		}
	}

	for name, cfg := range sources {
		src, err := cl.Source(ctx, cfg)
		if err != nil {
			return err
		}
		if srcrun := sourceHandlers[name]; srcrun != nil {
			g.Go(func() error { return srcrun(src).Run(ctx) })
		}
	}

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

	c.RelayEncryptions = overrides(c.RelayEncryptions, o.RelayEncryptions)

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

func mergeDestinationConfig(c, o DestinationConfig) DestinationConfig {
	n := DestinationConfig{
		Route:             override(c.Route, o.Route),
		RelayEncryptions:  overrides(c.RelayEncryptions, o.RelayEncryptions),
		ProxyProtoVersion: override(c.ProxyProtoVersion, o.ProxyProtoVersion),
	}

	if o.TCP.Addr != "" || o.TLS.Addr != "" || o.HTTP.StaticServerRoot != "" {
		n.TCP.Addr = o.TCP.Addr
		n.TLS.Addr = o.TLS.Addr
		n.TLS.CAsFile = o.TLS.CAsFile // TODO override?
		n.HTTP.StaticServerRoot = o.HTTP.StaticServerRoot
	}

	return n
}

func mergeSourceConfig(c, o SourceConfig) SourceConfig {
	n := SourceConfig{
		Route:            override(c.Route, o.Route),
		RelayEncryptions: overrides(c.RelayEncryptions, o.RelayEncryptions),
	}

	if o.TCP.Addr != "" || o.TLS.Addr != "" {
		n.TCP.Addr = o.TCP.Addr
		n.TLS.Addr = o.TLS.Addr
		n.TLS.CertFile = o.TLS.CertFile // TODO override?
		n.TLS.KeyFile = o.TLS.KeyFile
	}

	return n
}

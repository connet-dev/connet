package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/slogc"
	"github.com/connet-dev/connet/statusc"
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

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	rootCmd := clientCmd()
	rootCmd.AddCommand(serverCmd())
	rootCmd.AddCommand(controlCmd())
	rootCmd.AddCommand(relayCmd())
	rootCmd.AddCommand(checkCmd())
	rootCmd.AddCommand(generateKey())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.ExecuteContext(ctx); err != nil {
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

func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check <config-file>",
		Short: "Check a configuration file",
		Args:  cobra.ExactArgs(1),
	}

	cmd.RunE = wrapErr("run configuration check", func(_ *cobra.Command, args []string) error {
		cfg, err := loadConfigFrom(args[0])
		if err != nil {
			return err
		}

		if _, err := logger(cfg); err != nil {
			return err
		}

		return nil
	})

	return cmd
}

func generateKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-key",
		Short: "Generates ed25519 private/public key",
	}

	cmd.RunE = wrapErr("generate key", func(_ *cobra.Command, args []string) error {
		seed := make([]byte, ed25519.SeedSize)
		n, err := io.ReadFull(rand.Reader, seed)
		switch {
		case err != nil:
			return fmt.Errorf("rand read: %w", err)
		case n != ed25519.SeedSize:
			return fmt.Errorf("not enough data")
		}

		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Println("PRIVATE: ", netc.DNSSECEncoding.EncodeToString(seed))
		fmt.Println("PUBLIC:  ", netc.DNSSECEncoding.EncodeToString(pub))
		return nil
	})

	return cmd
}

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
	}

	cmd.RunE = wrapErr("print version", func(_ *cobra.Command, args []string) error {
		fmt.Println(model.BuildVersion())
		return nil
	})

	return cmd
}

func addConfigsFlag(cmd *cobra.Command) *[]string {
	return cmd.Flags().StringArray("config", nil, `configuration file(s) to load, merged when passed multiple times
  any explicit flags are merged last and override values from the configuration files`)
}

func (cfg *Config) addLogFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&cfg.LogLevel, "log-level", "", "log level, one of [fine, debug, info, warn, error] (defaults to 'info')")
	cmd.Flags().StringVar(&cfg.LogFormat, "log-format", "", "log formatter, one of [text, json] (defaults to 'text')")
}

func loadConfigs(files []string) (Config, error) {
	var merged Config

	for _, f := range files {
		cfg, err := loadConfigFrom(f)
		if err != nil {
			return Config{}, fmt.Errorf("load config %s: %w", f, err)
		}
		merged.merge(cfg)
	}

	return merged, nil
}

func loadConfigFrom(file string) (Config, error) {
	var cfg Config

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
	logger, err := slogc.New(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return nil, err
	}
	slog.SetDefault(logger)
	return logger, nil
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

func (c *Config) merge(o Config) {
	c.LogLevel = override(c.LogLevel, o.LogLevel)
	c.LogFormat = override(c.LogFormat, o.LogFormat)

	c.Server.merge(o.Server)
	c.Client.merge(o.Client)

	c.Control.merge(o.Control)
	c.Relay.merge(o.Relay)
}

func override[T comparable](s, o T) (result T) {
	if o != result {
		return o
	}
	return s
}

func overrides[T any](s, o []T) []T {
	if len(o) > 0 {
		return o
	}
	return s
}

func mergeSlices[S ~[]T, T interface{ merge(T) T }](c S, o S) S {
	if len(c) == len(o) {
		for i := range c {
			c[i] = c[i].merge(o[i])
		}
	} else if len(o) > 0 {
		return o
	}
	return c
}

func addStatusAddrFlag(cmd *cobra.Command, ref *string) {
	cmd.Flags().StringVar(ref, "status-addr", "", "status server address to listen for connections (TCP/HTTP, [host]:port) (disabled by default)")
}

type withStatus[T any] interface {
	Run(context.Context) error
	Status(context.Context) (T, error)
}

func runWithStatus[T any](ctx context.Context, srv withStatus[T], statusAddr *net.TCPAddr, logger *slog.Logger) error {
	if statusAddr == nil {
		return srv.Run(ctx)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return srv.Run(ctx) })
	g.Go(func() error {
		logger.Debug("running status server", "addr", statusAddr)
		return statusc.Run(ctx, statusAddr, srv.Status)
	})
	return g.Wait()
}

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/connet-dev/connet/model"
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
		Short: "check configuration file",
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

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "print version information",
	}

	cmd.RunE = wrapErr("run configuration check", func(_ *cobra.Command, args []string) error {
		fmt.Println(model.BuildVersion())
		return nil
	})

	return cmd
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
	return slogc.New(cfg.LogLevel, cfg.LogFormat)
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

func override(s, o string) string {
	if o != "" {
		return o
	}
	return s
}

func overrides(s, o []string) []string {
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

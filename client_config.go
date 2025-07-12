package connet

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/connet-dev/connet/nat"
	"github.com/quic-go/quic-go"
)

type clientConfig struct {
	token string

	controlAddr *net.UDPAddr
	controlHost string
	controlCAs  *x509.CertPool

	directAddr     *net.UDPAddr
	directResetKey *quic.StatelessResetKey

	natPMP nat.PMPConfig

	logger *slog.Logger
}

func newClientConfig(opts []ClientOption) (*clientConfig, error) {
	cfg := &clientConfig{
		natPMP: nat.PMPConfig{
			LocalResolver:   nat.LocalIPSystemResolver(),
			GatewayResolver: nat.GatewayIPSystemResolver(),
		},
		logger: slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.token == "" {
		if err := ClientTokenFromEnv()(cfg); err != nil {
			return nil, fmt.Errorf("default token: %w", err)
		}
	}

	if cfg.controlAddr == nil {
		if err := ClientControlAddress("127.0.0.1:19190")(cfg); err != nil {
			return nil, fmt.Errorf("default control address: %w", err)
		}
	}

	if cfg.directAddr == nil {
		if err := ClientDirectAddress(":19192")(cfg); err != nil {
			return nil, fmt.Errorf("default direct address: %w", err)
		}
	}

	if cfg.directResetKey == nil {
		if err := ClientDirectStatelessResetKeyFromEnv()(cfg); err != nil {
			return nil, fmt.Errorf("default stateless reset key: %w", err)
		}
		if cfg.directResetKey == nil {
			cfg.logger.Warn("running without a stateless reset key")
		}
	}

	return cfg, nil
}

type ClientOption func(cfg *clientConfig) error

func ClientToken(token string) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.token = token
		return nil
	}
}

func ClientTokenFromEnv() ClientOption {
	return func(cfg *clientConfig) error {
		if connetToken := os.Getenv("CONNET_TOKEN"); connetToken != "" {
			cfg.token = connetToken
		}
		return nil
	}
}

func ClientControlAddress(address string) ClientOption {
	return func(cfg *clientConfig) error {
		if i := strings.LastIndex(address, ":"); i < 0 {
			// missing :port, lets give it the default
			address = fmt.Sprintf("%s:%d", address, 19190)
		}
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return fmt.Errorf("resolve control address: %w", err)
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("split control address: %w", err)
		}

		cfg.controlAddr = addr
		cfg.controlHost = host

		return nil
	}
}

func ClientControlCAs(certFile string) ClientOption {
	return func(cfg *clientConfig) error {
		casData, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("read server CAs: %w", err)
		}

		cas := x509.NewCertPool()
		if !cas.AppendCertsFromPEM(casData) {
			return fmt.Errorf("missing server CA certificate in %s", certFile)
		}

		cfg.controlCAs = cas

		return nil
	}
}

func ClientDirectAddress(address string) ClientOption {
	return func(cfg *clientConfig) error {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return fmt.Errorf("resolve direct address: %w", err)
		}

		cfg.directAddr = addr

		return nil
	}
}

func ClientDirectStatelessResetKey(key *quic.StatelessResetKey) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.directResetKey = key
		return nil
	}
}

func ClientDirectStatelessResetKeyFile(path string) ClientOption {
	return func(cfg *clientConfig) error {
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read stateless reset key: %w", err)
		}
		if len(keyBytes) < 32 {
			return fmt.Errorf("stateless reset key len %d", len(keyBytes))
		}

		key := quic.StatelessResetKey(keyBytes)
		cfg.directResetKey = &key

		return nil
	}
}

func ClientDirectStatelessResetKeyFromEnv() ClientOption {
	return func(cfg *clientConfig) error {
		var name = fmt.Sprintf("stateless-reset-%s.key",
			strings.TrimPrefix(strings.ReplaceAll(cfg.directAddr.String(), ":", "-"), "-"))

		var path string
		if connetCacheDir := os.Getenv("CONNET_CACHE_DIR"); connetCacheDir != "" {
			// Support direct override if necessary, currently used in docker
			path = filepath.Join(connetCacheDir, name)
		} else if cacheDir := os.Getenv("CACHE_DIRECTORY"); cacheDir != "" {
			// Supports setting up the cache directory via systemd. For reference
			// https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RuntimeDirectory=
			path = filepath.Join(cacheDir, name)
		} else if userCacheDir, err := os.UserCacheDir(); err == nil {
			// Look for XDG_CACHE_HOME, fallback to $HOME/.cache
			dir := filepath.Join(userCacheDir, "connet")
			switch _, err := os.Stat(dir); {
			case err == nil:
				// the directory is already there, nothing to do
			case errors.Is(err, os.ErrNotExist):
				if err := os.Mkdir(dir, 0700); err != nil {
					return fmt.Errorf("mkdir cache dir: %w", err)
				}
			default:
				return fmt.Errorf("stat cache dir: %w", err)
			}

			path = filepath.Join(dir, name)
		} else {
			return nil
		}

		switch _, err := os.Stat(path); {
		case err == nil:
			keyBytes, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read stateless reset key: %w", err)
			}
			if len(keyBytes) < 32 {
				return fmt.Errorf("stateless reset key len %d", len(keyBytes))
			}
			key := quic.StatelessResetKey(keyBytes)
			cfg.directResetKey = &key
		case errors.Is(err, os.ErrNotExist):
			var key quic.StatelessResetKey
			if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
				return fmt.Errorf("generate stateless reset key: %w", err)
			}
			if err := os.WriteFile(path, key[:], 0600); err != nil {
				return fmt.Errorf("write stateless reset key: %w", err)
			}
			cfg.directResetKey = &key
		default:
			return fmt.Errorf("stat stateless reset key file: %w", err)
		}

		return nil
	}
}

func ClientNatPMPConfig(pmp nat.PMPConfig) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.natPMP = pmp
		return nil
	}
}

func ClientLogger(logger *slog.Logger) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.logger = logger
		return nil
	}
}

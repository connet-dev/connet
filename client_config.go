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

	"github.com/connet-dev/connet/client"
	"github.com/connet-dev/connet/model"
	"github.com/quic-go/quic-go"
)

type clientConfig struct {
	token string

	controlAddr *net.UDPAddr
	controlHost string
	controlCAs  *x509.CertPool

	directAddr     *net.UDPAddr
	directResetKey *quic.StatelessResetKey

	destinations map[model.Forward]client.DestinationConfig
	sources      map[model.Forward]client.SourceConfig

	logger *slog.Logger
}

type ClientOption func(cfg *clientConfig) error

func ClientToken(token string) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.token = token
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

func clientControlCAs(cas *x509.CertPool) ClientOption {
	return func(cfg *clientConfig) error {
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

func clientDirectStatelessResetKey() ClientOption {
	return func(cfg *clientConfig) error {
		var name = fmt.Sprintf("stateless-reset-%s.key",
			strings.TrimPrefix(strings.ReplaceAll(cfg.directAddr.String(), ":", "-"), "-"))

		var path string
		if cacheDir := os.Getenv("CACHE_DIRECTORY"); cacheDir != "" {
			path = filepath.Join(cacheDir, name)
		} else if userCacheDir, err := os.UserCacheDir(); err == nil {
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

func ClientDestination(dcfg client.DestinationConfig) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.destinations == nil {
			cfg.destinations = map[model.Forward]client.DestinationConfig{}
		}
		cfg.destinations[dcfg.Forward] = dcfg

		return nil
	}
}

func ClientSource(scfg client.SourceConfig) ClientOption {
	return func(cfg *clientConfig) error {
		if cfg.sources == nil {
			cfg.sources = map[model.Forward]client.SourceConfig{}
		}
		cfg.sources[scfg.Forward] = scfg

		return nil
	}
}

func ClientLogger(logger *slog.Logger) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.logger = logger
		return nil
	}
}

package connet

import (
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/selfhosted"
)

type serverConfig struct {
	clientsIngresses []control.Ingress
	clientsAuth      control.ClientAuthenticator

	relayAddr     *net.UDPAddr
	relayHostname string

	dir    string
	logger *slog.Logger
}

func newServerConfig(opts []ServerOption) (*serverConfig, error) {
	cfg := &serverConfig{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if len(cfg.clientsIngresses) == 0 {
		addr, err := net.ResolveUDPAddr("udp", ":19190")
		if err != nil {
			return nil, fmt.Errorf("resolve clients address: %w", err)
		}
		if err := ServerClientsIngress(control.Ingress{Addr: addr})(cfg); err != nil {
			return nil, fmt.Errorf("default clients address: %w", err)
		}
	}

	for i, ingress := range cfg.clientsIngresses {
		if ingress.TLS == nil {
			return nil, fmt.Errorf("ingress at %d is missing tls config", i)
		}
	}

	if cfg.relayAddr == nil {
		if err := ServerRelayAddress(":19191")(cfg); err != nil {
			return nil, fmt.Errorf("default relay address: %w", err)
		}
	}

	if cfg.relayHostname == "" {
		if err := ServerRelayHostname("localhost")(cfg); err != nil {
			return nil, fmt.Errorf("default relay hostname: %w", err)
		}
	}

	if cfg.dir == "" {
		if err := serverStoreDirTemp()(cfg); err != nil {
			return nil, fmt.Errorf("default store dir: %w", err)
		}
		cfg.logger.Info("using temporary store directory", "dir", cfg.dir)
	}

	return cfg, nil
}

type ServerOption func(*serverConfig) error

func ServerClientsIngress(icfg control.Ingress) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.clientsIngresses = append(cfg.clientsIngresses, icfg)

		return nil
	}
}

func ServerClientsTokens(tokens ...string) ServerOption {
	return func(cfg *serverConfig) error {
		auths := make([]selfhosted.ClientAuthentication, len(tokens))
		for i, t := range tokens {
			auths[i] = selfhosted.ClientAuthentication{Token: t}
		}

		cfg.clientsAuth = selfhosted.NewClientAuthenticator(auths...)

		return nil
	}
}

func ServerClientsAuthenticator(clientsAuth control.ClientAuthenticator) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.clientsAuth = clientsAuth

		return nil
	}
}

func ServerRelayAddress(address string) ServerOption {
	return func(cfg *serverConfig) error {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return fmt.Errorf("resolve relay address: %w", err)
		}

		cfg.relayAddr = addr

		return nil
	}
}

func ServerRelayHostname(hostname string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.relayHostname = hostname
		return nil
	}
}

func ServerStoreDir(dir string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.dir = dir
		return nil
	}
}

func serverStoreDirTemp() ServerOption {
	return func(cfg *serverConfig) error {
		tmpDir, err := os.MkdirTemp("", "connet-server-")
		if err != nil {
			return fmt.Errorf("create /tmp dir: %w", err)
		}
		cfg.dir = tmpDir
		return nil
	}
}

func ServerLogger(logger *slog.Logger) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.logger = logger
		return nil
	}
}

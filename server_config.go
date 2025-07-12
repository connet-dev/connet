package connet

import (
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/relay"
	"github.com/connet-dev/connet/selfhosted"
)

type serverConfig struct {
	clientsIngresses []control.Ingress
	clientsAuth      control.ClientAuthenticator

	relayIngresses []relay.Ingress

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

	if len(cfg.relayIngresses) == 0 {
		addr, err := net.ResolveUDPAddr("udp", ":19191")
		if err != nil {
			return nil, fmt.Errorf("resolve clients relay address: %w", err)
		}
		hps := []model.HostPort{{Host: "localhost", Port: 19191}}
		if err := ServerRelayIngress(relay.Ingress{Addr: addr, Hostports: hps})(cfg); err != nil {
			return nil, fmt.Errorf("default clients relay address: %w", err)
		}
	}

	if cfg.dir == "" {
		if err := serverStoreDir(cfg); err != nil {
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

func ServerRelayIngress(icfg relay.Ingress) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.relayIngresses = append(cfg.relayIngresses, icfg)

		return nil
	}
}

func ServerStoreDir(dir string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.dir = dir
		return nil
	}
}

func serverStoreDir(cfg *serverConfig) error {
	if stateDir := os.Getenv("CONNET_STATE_DIR"); stateDir != "" {
		// Support direct override if necessary, currently used in docker
		cfg.dir = stateDir
	} else if stateDir := os.Getenv("STATE_DIRECTORY"); stateDir != "" {
		// Supports setting up the state directory via systemd. For reference
		// https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RuntimeDirectory=
		cfg.dir = stateDir
	} else {
		tmpDir, err := os.MkdirTemp("", "connet-server-")
		if err != nil {
			return fmt.Errorf("create /tmp dir: %w", err)
		}
		cfg.dir = tmpDir
	}
	return nil
}

func ServerLogger(logger *slog.Logger) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.logger = logger
		return nil
	}
}

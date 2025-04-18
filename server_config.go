package connet

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/restr"
	"github.com/connet-dev/connet/selfhosted"
)

type serverConfig struct {
	cert tls.Certificate

	clientsAddr  *net.UDPAddr
	clientsAuth  control.ClientAuthenticator
	clientsRestr restr.IP

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

	if cfg.cert.Leaf == nil {
		return nil, fmt.Errorf("missing certificate")
	}

	if cfg.clientsAddr == nil {
		if err := ServerClientsAddress(":19190")(cfg); err != nil {
			return nil, fmt.Errorf("default clients address: %w", err)
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

func ServerCertificate(certFile, keyFile string) ServerOption {
	return func(cfg *serverConfig) error {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load server certificate: %w", err)
		}

		cfg.cert = cert

		return nil
	}
}

func ServerClientsAddress(address string) ServerOption {
	return func(cfg *serverConfig) error {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return fmt.Errorf("resolve clients address: %w", err)
		}

		cfg.clientsAddr = addr

		return nil
	}
}

func ServerClientRestrictions(allow []string, deny []string) ServerOption {
	return func(cfg *serverConfig) error {
		iprestr, err := restr.ParseIP(allow, deny)
		if err != nil {
			return fmt.Errorf("parse client restrictions: %w", err)
		}

		cfg.clientsRestr = iprestr

		return nil
	}
}

func ServerClientTokens(tokens ...string) ServerOption {
	return func(cfg *serverConfig) error {
		auths := make([]selfhosted.ClientAuthentication, len(tokens))
		for i, t := range tokens {
			auths[i] = selfhosted.ClientAuthentication{Token: t}
		}

		cfg.clientsAuth = selfhosted.NewClientAuthenticator(auths...)

		return nil
	}
}

func ServerClientAuthenticator(clientsAuth control.ClientAuthenticator) ServerOption {
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

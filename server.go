package connet

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/keihaya-com/connet/control"
	"github.com/keihaya-com/connet/relay"
	"github.com/keihaya-com/connet/selfhosted"
	"github.com/klev-dev/kleverr"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	serverConfig

	control *control.Server
	relay   *relay.Server
}

func NewServer(opts ...ServerOption) (*Server, error) {
	cfg := &serverConfig{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.controlAddr == nil {
		if err := ServerControlAddress(":19190")(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.relayAddr == nil {
		if err := ServerRelayAddress(":19191")(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.hostname == "" {
		switch {
		case len(cfg.relayCert.Leaf.DNSNames) > 0:
			if err := ServerHostname(cfg.relayCert.Leaf.DNSNames[0])(cfg); err != nil {
				return nil, err
			}
		case len(cfg.relayCert.Leaf.IPAddresses) > 0:
			if err := ServerHostname(cfg.relayCert.Leaf.IPAddresses[0].String())(cfg); err != nil {
				return nil, err
			}
		default:
			if err := ServerHostname("localhost")(cfg); err != nil {
				return nil, err
			}
		}
	}

	relayHostport := fmt.Sprintf("%s:%d", cfg.hostname, cfg.relayAddr.Port)
	rsync, err := selfhosted.NewRelaySync(relayHostport, cfg.relayCert.Leaf)
	if err != nil {
		return nil, err
	}

	control, err := control.NewServer(control.Config{
		Addr:   cfg.controlAddr,
		Cert:   cfg.controlCert,
		Auth:   cfg.auth,
		Relays: rsync,
		Logger: cfg.logger,
	})

	relay, err := relay.NewServer(relay.Config{
		Addr:   cfg.relayAddr,
		Cert:   cfg.relayCert,
		Auth:   rsync,
		Logger: cfg.logger,
	})
	if err != nil {
		return nil, err
	}

	return &Server{
		serverConfig: *cfg,

		control: control,
		relay:   relay,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return s.control.Run(ctx)
	})
	g.Go(func() error {
		return s.relay.Run(ctx)
	})
	return g.Wait()
}

type serverConfig struct {
	hostname string

	controlAddr *net.UDPAddr
	controlCert tls.Certificate

	relayAddr *net.UDPAddr
	relayCert tls.Certificate

	logger *slog.Logger
	auth   control.Authenticator
}

type ServerOption func(*serverConfig) error

func ServerTokens(tokens ...string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.auth = selfhosted.NewStaticAuthenticator(tokens...)
		return nil
	}
}

func ServerHostname(hostname string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.hostname = hostname
		return nil
	}
}

func ServerDefaultCertificate(certFile, keyFile string) ServerOption {
	return func(cfg *serverConfig) error {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return kleverr.Newf("default cert cannot be loaded: %w", err)
		}

		if cfg.controlCert.Leaf == nil {
			cfg.controlCert = cert
		}
		if cfg.relayCert.Leaf == nil {
			cfg.relayCert = cert
		}

		return nil
	}
}

func ServerControlAddress(address string) ServerOption {
	return func(cfg *serverConfig) error {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return kleverr.Newf("control address cannot be resolved: %w", err)
		}

		cfg.controlAddr = addr

		return nil
	}
}

func ServerControlCertificate(certFile, keyFile string) ServerOption {
	return func(cfg *serverConfig) error {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return kleverr.Newf("control cert cannot be loaded: %w", err)
		}

		cfg.controlCert = cert

		return nil
	}
}

func ServerRelayAddress(address string) ServerOption {
	return func(cfg *serverConfig) error {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return kleverr.Newf("relay address cannot be resolved: %w", err)
		}

		cfg.relayAddr = addr

		return nil
	}
}

func ServerRelayCertificate(certFile, keyFile string) ServerOption {
	return func(cfg *serverConfig) error {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return kleverr.Newf("relay cert cannot be loaded: %w", err)
		}

		cfg.relayCert = cert

		return nil
	}
}

func ServerLogger(logger *slog.Logger) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.logger = logger
		return nil
	}
}

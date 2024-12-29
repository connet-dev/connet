package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/relay"
	"github.com/connet-dev/connet/selfhosted"
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

	if cfg.relayHostname == "" {
		if err := ServerRelayHostname("localhost")(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.dir == "" {
		if err := serverStoreDirTemp()(cfg); err != nil {
			return nil, err
		}
	}

	relayControlToken := model.GenServerName("relay")

	control, err := control.NewServer(control.Config{
		Addr:       cfg.controlAddr,
		Cert:       cfg.controlCert,
		ClientAuth: cfg.clientAuth,
		RelayAuth:  selfhosted.NewRelayAuthenticator(relayControlToken),
		Logger:     cfg.logger,
		Stores:     control.NewFileStores(filepath.Join(cfg.dir, "control")),
	})

	controlCAs := x509.NewCertPool()
	controlCAs.AddCert(cfg.controlCert.Leaf)
	relay, err := relay.NewServer(relay.Config{
		Addr:     cfg.relayAddr,
		Hostport: model.HostPort{Host: cfg.relayHostname, Port: cfg.relayAddr.AddrPort().Port()},
		Logger:   cfg.logger,
		Stores:   relay.NewFileStores(filepath.Join(cfg.dir, "relay")),

		ControlAddr:  cfg.controlAddr,
		ControlHost:  "localhost",
		ControlToken: relayControlToken,
		ControlCAs:   controlCAs,
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
	clientAuth control.ClientAuthenticator

	controlAddr *net.UDPAddr
	controlCert tls.Certificate

	relayAddr     *net.UDPAddr
	relayHostname string

	dir    string
	logger *slog.Logger
}

type ServerOption func(*serverConfig) error

func ServerClientTokens(tokens ...string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.clientAuth = selfhosted.NewClientAuthenticator(tokens...)
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

func serverControlCertificate(cert tls.Certificate) ServerOption {
	return func(cfg *serverConfig) error {
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
			return err
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

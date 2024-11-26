package connet

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"

	"github.com/keihaya-com/connet/control"
	"github.com/keihaya-com/connet/relay"
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
		if err := ServerControlAddress("0.0.0.0:19190")(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.relayListenAddr == nil {
		if err := ServerRelayAddresses("0.0.0.0:19191", "localhost:19191")(cfg); err != nil {
			return nil, err
		}
	}

	store, err := relay.NewLocalStore(cfg.relayListenAddr.AddrPort(), cfg.relayPublicAddr)
	if err != nil {
		return nil, err
	}

	control, err := control.NewServer(control.Config{
		Addr:   cfg.controlAddr,
		Auth:   cfg.auth,
		Store:  store,
		Cert:   *cfg.certificate,
		Logger: cfg.logger,
	})

	relay, err := relay.NewServer(relay.Config{
		Addr:   cfg.relayListenAddr,
		Store:  store,
		Cert:   *cfg.certificate,
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
	controlAddr     *net.UDPAddr
	relayListenAddr *net.UDPAddr
	relayPublicAddr string

	certificate *tls.Certificate
	logger      *slog.Logger
	auth        control.Authenticator
}

type ServerOption func(*serverConfig) error

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

func ServerRelayAddresses(listen string, public string) ServerOption {
	return func(cfg *serverConfig) error {
		addr, err := net.ResolveUDPAddr("udp", listen)
		if err != nil {
			return kleverr.Newf("relay address cannot be resolved: %w", err)
		}
		cfg.relayListenAddr = addr
		cfg.relayPublicAddr = public
		return nil
	}
}

func ServerCertificate(cert, key string) ServerOption {
	return func(cfg *serverConfig) error {
		if cert, err := tls.LoadX509KeyPair(cert, key); err != nil {
			return err
		} else {
			cfg.certificate = &cert
			return nil
		}
	}
}

func ServerLogger(logger *slog.Logger) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.logger = logger
		return nil
	}
}

func ServerAuthenticator(auth control.Authenticator) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.auth = auth
		return nil
	}
}

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
	"github.com/connet-dev/connet/restr"
	"github.com/connet-dev/connet/selfhosted"
	"github.com/connet-dev/connet/statusc"
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
		cfg.logger.Info("using temporary store directory", "dir", cfg.dir)
	}

	relayControlToken := model.GenServerName("relay")
	relayAuth, err := selfhosted.NewRelayAuthenticator(relayControlToken)
	if err != nil {
		return nil, err
	}

	control, err := control.NewServer(control.Config{
		Addr:        cfg.controlAddr,
		Cert:        cfg.controlCert,
		ClientAuth:  cfg.clientAuth,
		ClientRestr: cfg.clientRestr,
		RelayAuth:   relayAuth,
		Logger:      cfg.logger,
		Stores:      control.NewFileStores(filepath.Join(cfg.dir, "control")),
	})
	if err != nil {
		return nil, err
	}

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
	g.Go(func() error { return s.control.Run(ctx) })
	g.Go(func() error { return s.relay.Run(ctx) })
	g.Go(func() error { return s.runStatus(ctx) })
	return g.Wait()
}

func (s *Server) runStatus(ctx context.Context) error {
	if s.statusAddr == nil {
		return nil
	}

	s.logger.Debug("running status server", "addr", s.statusAddr)
	return statusc.Run(ctx, s.statusAddr.String(), s.Status)
}

func (s *Server) Status(ctx context.Context) (ServerStatus, error) {
	control, err := s.control.Status(ctx)
	if err != nil {
		return ServerStatus{}, err
	}

	relay, err := s.relay.Status(ctx)
	if err != nil {
		return ServerStatus{}, err
	}

	return ServerStatus{control, relay}, nil
}

type ServerStatus struct {
	Control control.Status `json:"control"`
	Relay   relay.Status   `json:"relay"`
}

type serverConfig struct {
	clientAuth  control.ClientAuthenticator
	clientRestr restr.IPRestriction

	controlAddr *net.UDPAddr
	controlCert tls.Certificate

	relayAddr     *net.UDPAddr
	relayHostname string

	statusAddr *net.TCPAddr

	dir    string
	logger *slog.Logger
}

type ServerOption func(*serverConfig) error

func ServerClientTokens(tokens ...string) ServerOption {
	return func(cfg *serverConfig) error {
		clientAuth, err := selfhosted.NewClientAuthenticator(tokens...)
		if err != nil {
			return err
		}

		cfg.clientAuth = clientAuth

		return nil
	}
}

func ServerClientTokensRestricted(tokens []string, iprestr []restr.IPRestriction) ServerOption {
	return func(cfg *serverConfig) error {
		clientAuth, err := selfhosted.NewClientAuthenticatorRestricted(tokens, iprestr)
		if err != nil {
			return err
		}

		cfg.clientAuth = clientAuth

		return nil
	}
}

func ServerClientRestrictions(allow []string, deny []string) ServerOption {
	return func(cfg *serverConfig) error {
		iprestr, err := restr.ParseIPRestriction(allow, deny)
		if err != nil {
			return err
		}

		cfg.clientRestr = iprestr

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

func ServerStatusAddress(address string) ServerOption {
	return func(cfg *serverConfig) error {
		addr, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			return kleverr.Newf("status address cannot be resolved: %w", err)
		}

		cfg.statusAddr = addr

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

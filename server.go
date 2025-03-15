package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
			return nil, fmt.Errorf("server option: %w", err)
		}
	}

	if cfg.cert.Leaf == nil {
		return nil, fmt.Errorf("server missing certificate")
	}

	if cfg.clientsAddr == nil {
		if err := ServerClientsAddress(":19190")(cfg); err != nil {
			return nil, fmt.Errorf("server default clients address: %w", err)
		}
	}

	if cfg.relayAddr == nil {
		if err := ServerRelayAddress(":19191")(cfg); err != nil {
			return nil, fmt.Errorf("server default relay address: %w", err)
		}
	}

	if cfg.relayHostname == "" {
		if err := ServerRelayHostname("localhost")(cfg); err != nil {
			return nil, fmt.Errorf("server default relay hostname: %w", err)
		}
	}

	if cfg.dir == "" {
		if err := serverStoreDirTemp()(cfg); err != nil {
			return nil, fmt.Errorf("server default store dir: %w", err)
		}
		cfg.logger.Info("using temporary store directory", "dir", cfg.dir)
	}

	relaysAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:19189")
	if err != nil {
		return nil, fmt.Errorf("server relay address: %w", err)
	}
	relayAuth := selfhosted.RelayAuthentication{
		Token: model.GenServerName("relay"),
	}

	control, err := control.NewServer(control.Config{
		Cert:         cfg.cert,
		ClientsAddr:  cfg.clientsAddr,
		ClientsAuth:  cfg.clientsAuth,
		ClientsRestr: cfg.clientsRestr,
		RelaysAddr:   relaysAddr,
		RelaysAuth:   selfhosted.NewRelayAuthenticator(relayAuth),
		Logger:       cfg.logger,
		Stores:       control.NewFileStores(filepath.Join(cfg.dir, "control")),
	})
	if err != nil {
		return nil, fmt.Errorf("server control server: %w", err)
	}

	controlHost := "localhost"
	if len(cfg.cert.Leaf.IPAddresses) > 0 {
		controlHost = cfg.cert.Leaf.IPAddresses[0].String()
	} else if len(cfg.cert.Leaf.DNSNames) > 0 {
		controlHost = cfg.cert.Leaf.DNSNames[0]
	}
	controlCAs := x509.NewCertPool()
	controlCAs.AddCert(cfg.cert.Leaf)
	relay, err := relay.NewServer(relay.Config{
		Addr:     cfg.relayAddr,
		Hostport: model.HostPort{Host: cfg.relayHostname, Port: cfg.relayAddr.AddrPort().Port()},
		Logger:   cfg.logger,
		Stores:   relay.NewFileStores(filepath.Join(cfg.dir, "relay")),

		ControlAddr:  relaysAddr,
		ControlHost:  controlHost,
		ControlToken: relayAuth.Token,
		ControlCAs:   controlCAs,
	})
	if err != nil {
		return nil, fmt.Errorf("server relay server: %w", err)
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
	cert tls.Certificate

	clientsAddr  *net.UDPAddr
	clientsAuth  control.ClientAuthenticator
	clientsRestr restr.IP

	relayAddr     *net.UDPAddr
	relayHostname string

	statusAddr *net.TCPAddr

	dir    string
	logger *slog.Logger
}

type ServerOption func(*serverConfig) error

func ServerCertificate(certFile, keyFile string) ServerOption {
	return func(cfg *serverConfig) error {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("server control cert: %w", err)
		}

		cfg.cert = cert

		return nil
	}
}

func ServerClientsAddress(address string) ServerOption {
	return func(cfg *serverConfig) error {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return fmt.Errorf("server control address: %w", err)
		}

		cfg.clientsAddr = addr

		return nil
	}
}

func ServerClientRestrictions(allow []string, deny []string) ServerOption {
	return func(cfg *serverConfig) error {
		iprestr, err := restr.ParseIP(allow, deny)
		if err != nil {
			return err
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
			return fmt.Errorf("server relay address: %w", err)
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
			return fmt.Errorf("server status address: %w", err)
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
			return fmt.Errorf("server create tmp dir: %w", err)
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

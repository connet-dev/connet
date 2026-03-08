package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"

	"github.com/connet-dev/connet/pkg/certc"
	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/server/control"
	"github.com/connet-dev/connet/server/relay"
	"github.com/connet-dev/connet/server/selfhosted"
)


type Server struct {
	serverConfig

	control *control.Server
	relay   *relay.Server

	readyCh chan error
	doneCh  chan error
}

func New(opts ...Option) (*Server, error) {
	cfg, err := newServerConfig(opts)
	if err != nil {
		return nil, err
	}

	relayRootCert, err := certc.NewRoot()
	if err != nil {
		return nil, fmt.Errorf("generate relays root cert: %w", err)
	}

	relaysAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:19189")
	if err != nil {
		return nil, fmt.Errorf("resolve relays address: %w", err)
	}
	relaysCert, err := relayRootCert.NewServer(certc.CertOpts{
		IPs: []net.IP{relaysAddr.IP},
	})
	if err != nil {
		return nil, fmt.Errorf("generate relays cert: %w", err)
	}
	relaysCAs, err := relaysCert.CertPool()
	if err != nil {
		return nil, fmt.Errorf("get relays CAs: %w", err)
	}
	relaysTLSCert, err := relaysCert.TLSCert()
	if err != nil {
		return nil, fmt.Errorf("get relays TLS cert: %w", err)
	}

	relayAuth := selfhosted.RelayAuthentication{
		Token: netc.GenDomainName("relay.control"),
	}

	control, err := control.NewServer(control.Config{
		ClientsIngress:        cfg.clientsIngresses,
		ClientsAuth:           cfg.clientsAuth,
		ClientsEndpointExpiry: cfg.clientsEndpointExpiry,

		RelaysIngress: []control.Ingress{{
			Addr: relaysAddr,
			TLS: &tls.Config{
				Certificates: []tls.Certificate{relaysTLSCert},
			},
		}},
		RelaysAuth: selfhosted.NewRelayAuthenticator(relayAuth),

		Stores: control.NewFileStores(filepath.Join(cfg.dir, "control")),
		Logger: cfg.logger,

		DrainTimeout: cfg.drainTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("create control server: %w", err)
	}

	relay, err := relay.NewServer(relay.Config{
		Metadata: "embedded relay",

		ControlAddr:  relaysAddr,
		ControlHost:  relaysTLSCert.Leaf.IPAddresses[0].String(),
		ControlToken: relayAuth.Token,
		ControlCAs:   relaysCAs,

		Ingress: cfg.relayIngresses,

		Stores: relay.NewFileStores(filepath.Join(cfg.dir, "relay")),
		Logger: cfg.logger,

		DrainTimeout: cfg.drainTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("create relay server: %w", err)
	}

	return &Server{
		serverConfig: *cfg,

		control: control,
		relay:   relay,

		readyCh: make(chan error, 1),
		doneCh:  make(chan error, 1),
	}, nil
}

// Ready returns a channel that receives nil when the server is ready to accept traffic,
// or a non-nil error if startup failed. The channel is then closed.
func (s *Server) Ready() <-chan error {
	return s.readyCh
}

// Done returns a channel that receives nil on clean shutdown, or an error on unclean shutdown.
// The channel is then closed. Sent after all connections and streams have drained.
func (s *Server) Done() <-chan error {
	return s.doneCh
}

func (s *Server) Run(ctx context.Context) error {
	notifyReady := reliable.ReadyNotifier(2, s.readyCh)
	for _, ch := range []<-chan error{s.control.Ready(), s.relay.Ready()} {
		ch := ch
		go func() { notifyReady(<-ch) }()
	}

	g := reliable.NewGroup(ctx)
	g.Go(s.control.Run)
	g.Go(s.relay.Run)
	err := g.Wait()

	s.doneCh <- err
	close(s.doneCh)
	return err
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

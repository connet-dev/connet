package connet

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/relay"
	"github.com/connet-dev/connet/selfhosted"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	serverConfig

	control *control.Server
	relay   *relay.Server
}

func NewServer(opts ...ServerOption) (*Server, error) {
	cfg, err := newServerConfig(opts)
	if err != nil {
		return nil, err
	}

	rootCert, err := certc.NewRoot()
	if err != nil {
		return nil, fmt.Errorf("generate relays root cert: %w", err)
	}

	relaysAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:19189")
	if err != nil {
		return nil, fmt.Errorf("resolve relays address: %w", err)
	}
	relaysCert, err := rootCert.NewServer(certc.CertOpts{
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
		Token: netc.GenServerName("relay"),
	}

	control, err := control.NewServer(control.Config{
		ClientsIngress: cfg.clientsIngresses,
		ClientsAuth:    cfg.clientsAuth,
		RelaysIngress: []control.Ingress{{
			Addr: relaysAddr,
			TLS: &tls.Config{
				Certificates: []tls.Certificate{relaysTLSCert},
			},
		}},
		RelaysAuth: selfhosted.NewRelayAuthenticator(relayAuth),
		Logger:     cfg.logger,
		Stores:     control.NewFileStores(filepath.Join(cfg.dir, "control")),
	})
	if err != nil {
		return nil, fmt.Errorf("create control server: %w", err)
	}

	relay, err := relay.NewServer(relay.Config{
		Ingress: []model.IngressConfig{
			{Addr: cfg.relayAddr},
		},
		Hostports: []model.HostPort{{Host: cfg.relayHostname, Port: cfg.relayAddr.AddrPort().Port()}},
		Logger:    cfg.logger,
		Stores:    relay.NewFileStores(filepath.Join(cfg.dir, "relay")),

		ControlAddr:  relaysAddr,
		ControlHost:  relaysTLSCert.Leaf.IPAddresses[0].String(),
		ControlToken: relayAuth.Token,
		ControlCAs:   relaysCAs,
	})
	if err != nil {
		return nil, fmt.Errorf("create relay server: %w", err)
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
	return g.Wait()
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

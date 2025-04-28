package connet

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"path/filepath"

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

	relaysAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:19189")
	if err != nil {
		return nil, fmt.Errorf("resolve relays address: %w", err)
	}
	relayAuth := selfhosted.RelayAuthentication{
		Token: netc.GenServerName("relay"),
	}

	control, err := control.NewServer(control.Config{
		ClientsIngress: cfg.clientsIngresses,
		ClientsAuth:    cfg.clientsAuth,
		RelaysIngress: []control.Ingress{{
			Addr: relaysAddr,
			TLS:  cfg.clientsIngresses[0].TLS, // TODO should choose one of the certs and use that, controlHost
		}},
		RelaysAuth: selfhosted.NewRelayAuthenticator(relayAuth),
		Logger:     cfg.logger,
		Stores:     control.NewFileStores(filepath.Join(cfg.dir, "control")),
	})
	if err != nil {
		return nil, fmt.Errorf("create control server: %w", err)
	}

	controlHost := "localhost"
	controlCAs := x509.NewCertPool()
	for _, ingress := range cfg.clientsIngresses {
		for _, cert := range ingress.TLS.Certificates {
			if len(cert.Leaf.IPAddresses) > 0 {
				controlHost = cert.Leaf.IPAddresses[0].String()
			} else if len(cert.Leaf.DNSNames) > 0 {
				controlHost = cert.Leaf.DNSNames[0]
			}
			controlCAs.AddCert(cert.Leaf)
		}
	}
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

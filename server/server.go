package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/relay"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/selfhosted"
)

type Server struct {
	serverConfig

	control *control.Server
	relay   *relay.Server
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
		Token: netc.GenName(),
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

		Stores: control.NewFileStores(filepath.Join(cfg.dir, "control")),
		Logger: cfg.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("create control server: %w", err)
	}

	relay, err := relay.NewServer(relay.Config{
		ControlAddr:  relaysAddr,
		ControlHost:  relaysTLSCert.Leaf.IPAddresses[0].String(),
		ControlToken: relayAuth.Token,
		ControlCAs:   relaysCAs,

		Ingress: cfg.relayIngresses,

		Stores: relay.NewFileStores(filepath.Join(cfg.dir, "relay")),
		Logger: cfg.logger,
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
	g := reliable.NewGroup(ctx)
	g.Go(s.control.Run)
	g.Go(s.relay.Run)
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

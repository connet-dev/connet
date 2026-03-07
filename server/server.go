package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"

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

	once sync.Once
	done chan struct{}
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

func (s *Server) Start() error {
	var startErr error
	s.once.Do(func() {
		controlReady := make(chan error, 1)
		go func() { controlReady <- s.control.Start() }()
		relayReady := make(chan error, 1)
		go func() { relayReady <- s.relay.Start() }()

		controlErr := <-controlReady
		relayErr := <-relayReady
		if err := errors.Join(controlErr, relayErr); err != nil {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), reliable.DefaultStopTimeout)
			defer stopCancel()
			_ = s.Stop(stopCtx)
			startErr = err
			return
		}

		s.done = make(chan struct{})
		go func() {
			select {
			case <-s.control.Done():
			case <-s.relay.Done():
			}
			close(s.done)
		}()
	})
	return startErr
}

func (s *Server) Done() <-chan struct{} {
	return s.done
}

func (s *Server) Stop(ctx context.Context) error {
	controlErr := make(chan error, 1)
	relayErr := make(chan error, 1)
	go func() { controlErr <- s.control.Stop(ctx) }()
	go func() { relayErr <- s.relay.Stop(ctx) }()
	return errors.Join(<-controlErr, <-relayErr)
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

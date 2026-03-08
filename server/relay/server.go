package relay

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/certc"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/notify"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/statusc"
	"github.com/quic-go/quic-go"
)

func newDrainCtx(ctx context.Context, fn func(context.Context) time.Duration) (context.Context, context.CancelFunc) {
	d := 30 * time.Second
	if fn != nil {
		d = fn(ctx)
	}
	return context.WithTimeout(context.Background(), d)
}

type Config struct {
	Metadata string

	ControlAddr  *net.UDPAddr
	ControlHost  string
	ControlToken string
	ControlCAs   *x509.CertPool

	HandshakeIdleTimeout time.Duration

	Ingress []Ingress

	Stores Stores

	Logger *slog.Logger

	DrainTimeout func(ctx context.Context) time.Duration
}

func NewServer(cfg Config) (*Server, error) {
	if len(cfg.Ingress) == 0 {
		return nil, fmt.Errorf("relay server is missing ingresses")
	}

	configStore, err := cfg.Stores.Config()
	if err != nil {
		return nil, fmt.Errorf("relay stores: %w", err)
	}

	if err := cfg.Stores.RemoveDeprecated(); err != nil {
		cfg.Logger.Warn("could not remove deprecated stores", "err", err)
	}

	statelessResetVal, err := configStore.GetOrInit(configStatelessReset, func(ck ConfigKey) (ConfigValue, error) {
		var key quic.StatelessResetKey
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return ConfigValue{}, fmt.Errorf("generate rand: %w", err)
		}
		return ConfigValue{Bytes: key[:]}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("relay stateless reset key: %w", err)
	}
	var statelessResetKey quic.StatelessResetKey
	copy(statelessResetKey[:], statelessResetVal.Bytes)

	rootCert, err := certc.NewRoot()
	if err != nil {
		return nil, fmt.Errorf("generate relay cert: %w", err)
	}

	clientsCert, err := rootCert.NewServer(certc.CertOpts{
		Domains: []string{netc.GenDomainName("reserve.relay")},
	})
	if err != nil {
		return nil, fmt.Errorf("generate client relay cert: %w", err)
	}

	control, err := newControlClient(cfg, clientsCert, configStore)
	if err != nil {
		return nil, fmt.Errorf("relay control client: %w", err)
	}

	clients, err := newClientsServer(cfg, clientsCert, control)
	if err != nil {
		return nil, fmt.Errorf("relay clients server: %w", err)
	}

	return &Server{
		ingress:           cfg.Ingress,
		statelessResetKey: &statelessResetKey,

		control: control,
		clients: clients,

		drainTimeout: cfg.DrainTimeout,
		readyCh:      make(chan error, 1),
		doneCh:       make(chan error, 1),
	}, nil
}

type Server struct {
	ingress           []Ingress
	statelessResetKey *quic.StatelessResetKey

	control *controlClient
	clients *clientsServer

	drainTimeout func(ctx context.Context) time.Duration
	readyCh      chan error
	doneCh       chan error
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
	n := len(s.ingress)
	notifyReady := reliable.ReadyNotifier(n, s.readyCh)

	err := s.run(ctx, notifyReady)

	drainCtx, cancel := newDrainCtx(ctx, s.drainTimeout)
	defer cancel()
	s.clients.waitDrain(drainCtx)

	s.doneCh <- err
	close(s.doneCh)
	return err
}

func (s *Server) run(ctx context.Context, notifyReady func(error)) error {
	transports := notify.NewEmpty[[]*quic.Transport]()
	var waitForTransport TransportsFn = func(ctx context.Context) ([]*quic.Transport, error) {
		t, _, err := transports.GetAny(ctx)
		return t, err
	}

	g := reliable.NewGroup(ctx)

	for _, ingress := range s.ingress {
		cfg := clientsServerCfg{
			ingress:           ingress,
			statelessResetKey: s.statelessResetKey,
			addedTransport: func(t *quic.Transport) {
				notify.SliceAppend(transports, t)
			},
			removeTransport: func(t *quic.Transport) {
				notify.SliceRemove(transports, t)
			},
		}
		g.Go(func(ctx context.Context) error { return s.clients.run(ctx, cfg, notifyReady) })
	}

	g.Go(reliable.Bind(waitForTransport, s.control.run))

	return g.Wait()
}

type Status struct {
	Status       statusc.Status            `json:"status"`
	BuildVersion string                    `json:"build-version"`
	Hostports    []string                  `json:"hostports"`
	ServerAddr   string                    `json:"server-address"`
	ServerID     string                    `json:"server-id"`
	Endpoints    map[string]EndpointStatus `json:"endpoints"`
}

type EndpointStatus struct {
	Endpoint     model.Endpoint                   `json:"endpoint"`
	Destinations map[model.Key]EndpointPeerStatus `json:"destinations"`
	Sources      map[model.Key]EndpointPeerStatus `json:"sources"`
}

type EndpointPeerStatus struct {
	Key      model.Key `json:"key"`
	Metadata string    `json:"metadata"`
}

func (s *Server) Status(ctx context.Context) (Status, error) {
	stat := s.control.connStatus.Load().(statusc.Status)

	controlID, err := s.getControlID()
	if err != nil {
		return Status{}, err
	}

	eps := s.getEndpoints()

	return Status{
		Status:       stat,
		BuildVersion: model.BuildVersion(),
		Hostports:    iterc.MapSliceStrings(s.control.hostports),
		ServerAddr:   s.control.controlAddr.String(),
		ServerID:     controlID,
		Endpoints:    eps,
	}, nil
}

func (s *Server) getControlID() (string, error) {
	controlIDConfig, err := s.control.config.GetOrDefault(configControlID, ConfigValue{})
	if err != nil {
		return "", err
	}
	return controlIDConfig.String, nil
}

func (s *Server) getEndpoints() map[string]EndpointStatus {
	s.clients.endpointsMu.RLock()
	defer s.clients.endpointsMu.RUnlock()

	endpoints := map[string]EndpointStatus{}
	for ep, v := range s.clients.endpoints {
		endpoints[ep.String()] = EndpointStatus{
			Endpoint:     ep,
			Destinations: s.getDestinations(v),
			Sources:      s.getSources(v),
		}
	}
	return endpoints
}

func (s *Server) getDestinations(cls *endpointClients) map[model.Key]EndpointPeerStatus {
	result := map[model.Key]EndpointPeerStatus{}

	cls.mu.RLock()
	defer cls.mu.RUnlock()

	for k, dst := range cls.destinations {
		result[k] = EndpointPeerStatus{
			Key:      k,
			Metadata: dst.auth.metadata,
		}
	}

	return result
}

func (s *Server) getSources(cls *endpointClients) map[model.Key]EndpointPeerStatus {
	result := map[model.Key]EndpointPeerStatus{}

	cls.mu.RLock()
	defer cls.mu.RUnlock()

	for k, dst := range cls.sources {
		result[k] = EndpointPeerStatus{
			Key:      k,
			Metadata: dst.auth.metadata,
		}
	}

	return result
}

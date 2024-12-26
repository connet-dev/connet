package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"

	"github.com/keihaya-com/connet/model"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr     *net.UDPAddr
	Hostport model.HostPort
	Logger   *slog.Logger
	Stores   Stores

	ControlAddr  *net.UDPAddr
	ControlHost  string
	ControlToken string
	ControlCAs   *x509.CertPool
}

func NewServer(cfg Config) (*Server, error) {
	control, err := newControlClient(cfg)
	if err != nil {
		return nil, err
	}

	clients, err := newClientsServer(cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{
		addr: cfg.Addr,

		control: control,
		clients: clients,

		logger: cfg.Logger.With("relay", cfg.Hostport),
	}

	s.clients.tlsConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		return s.control.clientTLSConfig(chi, s.clients.tlsConf)
	}
	s.clients.auth = s.control.authenticate

	return s, nil
}

type Server struct {
	addr *net.UDPAddr

	control *controlClient
	clients *clientsServer

	logger *slog.Logger
}

func (s *Server) Run(ctx context.Context) error {
	s.logger.Debug("start udp listener")
	udpConn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer udpConn.Close()

	s.logger.Debug("start quic listener")
	transport := &quic.Transport{
		Conn: udpConn,
		// TODO review other options
	}
	defer transport.Close()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.control.run(ctx, transport) })
	g.Go(func() error { return s.clients.run(ctx, transport) })

	return g.Wait()
}

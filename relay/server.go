package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr     *net.UDPAddr
	Hostport model.HostPort
	Logger   *slog.Logger

	ControlAddr  *net.UDPAddr
	ControlHost  string
	ControlToken string
	ControlCAs   *x509.CertPool
}

func NewServer(cfg Config) (*Server, error) {
	root, err := certc.NewRoot()
	if err != nil {
		return nil, err
	}

	s := &Server{
		addr: cfg.Addr,

		control: &controlClient{
			hostport: cfg.Hostport,

			controlAddr:  cfg.ControlAddr,
			controlToken: cfg.ControlToken,
			controlTlsConf: &tls.Config{
				ServerName: cfg.ControlHost,
				RootCAs:    cfg.ControlCAs,
				NextProtos: []string{"connet-relays"},
			},

			serversRoot:      root,
			serversByForward: notify.NewEmpty[map[model.Forward]*relayServer](),
			serversByName:    map[string]*relayServer{},

			logger: cfg.Logger.With("relay-control", cfg.Hostport),
		},

		clients: &clientsServer{
			tlsConf: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				NextProtos: []string{"connet-relay"},
			},

			forwards: map[model.Forward]*forwardClients{},

			logger: cfg.Logger.With("relay-clients", cfg.Hostport),
		},

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
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer conn.Close()

	s.logger.Debug("start quic listener")
	tr := &quic.Transport{
		Conn: conn,
		// TODO review other options
	}
	defer tr.Close()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.control.run(ctx, tr) })
	g.Go(func() error { return s.clients.run(ctx, tr) })

	return g.Wait()
}

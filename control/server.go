package control

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"time"

	"github.com/connet-dev/connet/netc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr        *net.UDPAddr
	Cert        tls.Certificate
	ClientAuth  ClientAuthenticator
	ClientRestr netc.IPRestriction
	RelayAuth   RelayAuthenticator
	RelayRestr  netc.IPRestriction
	Stores      Stores
	Logger      *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	config, err := cfg.Stores.Config()
	if err != nil {
		return nil, err
	}

	s := &Server{
		addr: cfg.Addr,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cfg.Cert},
			NextProtos:   []string{"connet", "connet-relays"},
		},
		logger: cfg.Logger.With("control", cfg.Addr),
	}

	relays, err := newRelayServer(cfg.RelayAuth, cfg.RelayRestr, config, cfg.Stores, cfg.Logger)
	if err != nil {
		return nil, err
	}
	s.relays = relays

	clients, err := newClientServer(cfg.ClientAuth, cfg.ClientRestr, s.relays, config, cfg.Stores, cfg.Logger)
	if err != nil {
		return nil, err
	}
	s.clients = clients

	s.status = &statusServer{
		clients: clients,
		relays:  relays,
		logger:  cfg.Logger.With("control", "status"),
	}

	return s, nil
}

type Server struct {
	addr    *net.UDPAddr
	tlsConf *tls.Config
	logger  *slog.Logger

	clients *clientServer
	relays  *relayServer
	status  *statusServer
}

func (s *Server) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.relays.run(ctx) })
	g.Go(func() error { return s.clients.run(ctx) })
	g.Go(func() error { return s.status.run(ctx) })
	g.Go(func() error { return s.runListener(ctx) })

	return g.Wait()
}

func (s *Server) runListener(ctx context.Context) error {
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

	l, err := transport.Listen(s.tlsConf, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return kleverr.Ret(err)
	}
	defer l.Close()

	s.logger.Info("waiting for connections")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			s.logger.Debug("accept error", "err", err)
			return kleverr.Ret(err)
		}

		switch conn.ConnectionState().TLS.NegotiatedProtocol {
		case "connet":
			s.logger.Info("new client connected", "remote", conn.RemoteAddr())
			s.clients.handle(ctx, conn)
		case "connet-relays":
			s.logger.Info("new relay connected", "remote", conn.RemoteAddr())
			s.relays.handle(ctx, conn)
		default:
			s.logger.Debug("unknown connected", "remote", conn.RemoteAddr())
			conn.CloseWithError(1, "unknown protocol")
		}
	}
}

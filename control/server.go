package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/keihaya-com/connet/logc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr       *net.UDPAddr
	Cert       tls.Certificate
	ClientAuth ClientAuthenticator
	RelayAuth  RelayAuthenticator
	Logger     *slog.Logger
	Dir        string
}

func NewServer(cfg Config) (*Server, error) {
	relayClients, err := logc.NewKV[relayClientKey, relayClientValue](filepath.Join(cfg.Dir, "relay-clients"))
	if err != nil {
		return nil, err
	}

	relayServers, err := logc.NewKV[relayServerKey, relayServerValue](filepath.Join(cfg.Dir, "relay-servers"))
	if err != nil {
		return nil, err
	}

	relayOffsets, err := logc.NewKV[model.HostPort, int64](filepath.Join(cfg.Dir, "relay-offsets"))
	if err != nil {
		return nil, err
	}

	clients, err := logc.NewKV[clientKey, clientValue](filepath.Join(cfg.Dir, "control-clients"))
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
	s.relays = &relayServer{
		id:     ksuid.New(),
		auth:   cfg.RelayAuth,
		logger: cfg.Logger.With("server", "relays"),

		relayClients: relayClients,
		relayServers: relayServers,
		relayOffsets: relayOffsets,

		forwardsCache:  map[model.Forward]map[model.HostPort]*x509.Certificate{},
		forwardsOffset: logc.OffsetOldest,
	}
	s.clients = &clientServer{
		auth:   cfg.ClientAuth,
		relays: s.relays,
		encode: cfg.Cert.Leaf.Raw,
		logger: cfg.Logger.With("server", "clients"),

		clients: clients,

		clientsCache:  map[cacheKey][]*pbs.ServerPeer{},
		clientsOffset: logc.OffsetOldest,
	}
	return s, nil
}

type Server struct {
	addr    *net.UDPAddr
	tlsConf *tls.Config
	logger  *slog.Logger

	clients *clientServer
	relays  *relayServer
}

func (s *Server) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.relays.run(ctx) })
	g.Go(func() error { return s.clients.run(ctx) })
	g.Go(func() error { return s.runListener(ctx) })

	return g.Wait()
}

func (s *Server) runListener(ctx context.Context) error {
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

	l, err := tr.Listen(s.tlsConf, &quic.Config{
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
			if errors.Is(err, context.Canceled) {
				err = context.Cause(ctx)
			}
			s.logger.Warn("accept error", "err", err)
			return kleverr.Ret(err)
		}
		s.logger.Info("connection accepted", "remote", conn.RemoteAddr(), "proto", conn.ConnectionState().TLS.NegotiatedProtocol)

		switch conn.ConnectionState().TLS.NegotiatedProtocol {
		case "connet":
			if err := s.clients.handle(ctx, conn); err != nil {
				return err
			}
		case "connet-relays":
			if err := s.relays.handle(ctx, conn); err != nil {
				return err
			}
		default:
			conn.CloseWithError(1, "unknown protocol")
		}
	}
}

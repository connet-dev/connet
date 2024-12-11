package control

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
)

type Config struct {
	Addr   *net.UDPAddr
	Cert   tls.Certificate
	Auth   ClientAuthenticator
	Relays Relays
	Logger *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	return &Server{
		addr:       cfg.Addr,
		clientAuth: cfg.Auth,
		relays:     cfg.Relays,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cfg.Cert},
			NextProtos:   []string{"connet", "connet-relays"},
		},
		logger: cfg.Logger.With("control", cfg.Addr),

		whisperer: newWhisperer(),
	}, nil
}

type Server struct {
	addr       *net.UDPAddr
	clientAuth ClientAuthenticator
	relayAuth  RelayAuthenticator
	relays     Relays
	tlsConf    *tls.Config
	logger     *slog.Logger

	whisperer *whisperer
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
		s.logger.Info("client connected", "local", conn.LocalAddr(), "remote", conn.RemoteAddr())

		switch conn.ConnectionState().TLS.NegotiatedProtocol {
		case "connet":
			cc := &clientConn{
				server: s,
				conn:   conn,
				logger: s.logger,
			}
			go cc.run(ctx)
		case "connet-relays":
			rc := &relayConn{
				server: s,
				conn:   conn,
				logger: s.logger,
			}
			go rc.run(ctx)
		default:
			conn.CloseWithError(1, "unknown protocol")
		}
	}
}

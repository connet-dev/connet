package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"slices"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/slogc"
	"github.com/quic-go/quic-go"
)

type tlsAuthenticator func(chi *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error)

func newClientsServer(cfg Config, tlsAuth tlsAuthenticator, clAuth clientAuthenticator, rootCert *certc.Cert, directCert *certc.Cert) (*clientsServer, error) {
	directTLS, err := directCert.TLSCert()
	if err != nil {
		return nil, fmt.Errorf("direct TLS cert: %w", err)
	}

	s := &clientsServer{
		tlsConf: &tls.Config{
			ServerName:   directTLS.Leaf.DNSNames[0],
			Certificates: []tls.Certificate{directTLS},
			ClientAuth:   tls.RequireAnyClientCert,
			NextProtos:   model.ConnectRelayNextProtos,
		},
		controlAuth: tlsAuth,

		controlServer: &clientsControlServer{
			auth: clAuth,

			endpoints: map[model.Endpoint]*endpointServer{},

			logger: cfg.Logger.With("server", "relay-control-clients"),
		},

		directServer: &clientsDirectServer{
			rootCert: rootCert,

			peerServers: map[string]*directPeerServer{},

			logger: cfg.Logger.With("server", "relay-direct-clients"),
		},

		logger: cfg.Logger.With("server", "relay-clients"),
	}

	s.tlsConf.GetConfigForClient = s.tlsAuth

	return s, nil
}

type clientsServer struct {
	tlsConf     *tls.Config
	controlAuth tlsAuthenticator

	controlServer *clientsControlServer
	directServer  *clientsDirectServer

	logger *slog.Logger
}

func (s *clientsServer) tlsAuth(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	if netc.IsSubdomain(chi.ServerName, "connet.control.relay") && slices.Contains(chi.SupportedProtos, model.CRv01.String()) {
		return s.controlAuth(chi, s.tlsConf)
	}
	if netc.IsSubdomain(chi.ServerName, "connet.relay") && slices.Contains(chi.SupportedProtos, model.CRv02.String()) {
		s.directServer.peerServersMu.RLock()
		srv := s.directServer.peerServers[chi.ServerName]
		s.directServer.peerServersMu.RUnlock()

		if srv != nil {
			return srv.tlsConf.Load(), nil
		}
	}
	return s.tlsConf, nil
}

type clientsServerCfg struct {
	ingress           Ingress
	statelessResetKey *quic.StatelessResetKey
	addedTransport    func(*quic.Transport)
	removeTransport   func(*quic.Transport)
}

func (s *clientsServer) run(ctx context.Context, cfg clientsServerCfg) error {
	s.logger.Debug("start udp listener", "addr", cfg.ingress.Addr)
	udpConn, err := net.ListenUDP("udp", cfg.ingress.Addr)
	if err != nil {
		return fmt.Errorf("relay server listen: %w", err)
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			slogc.Fine(s.logger, "error closing udp listener", "err", err)
		}
	}()

	s.logger.Debug("start quic listener", "addr", cfg.ingress.Addr)
	transport := quicc.ServerTransport(udpConn, cfg.statelessResetKey)
	defer func() {
		if err := transport.Close(); err != nil {
			slogc.Fine(s.logger, "error closing transport", "err", err)
		}
	}()

	cfg.addedTransport(transport)
	defer cfg.removeTransport(transport)

	quicConf := quicc.ServerConfig()
	if cfg.ingress.Restr.IsNotEmpty() {
		quicConf = quicConf.Clone()
		quicConf.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
			if cfg.ingress.Restr.IsAllowedAddr(info.RemoteAddr) {
				return quicConf, nil
			}
			return nil, fmt.Errorf("client not allowed from %s", info.RemoteAddr.String())
		}
	}

	l, err := transport.Listen(s.tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("client server udp listen: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			slogc.Fine(s.logger, "error closing clients listener", "err", err)
		}
	}()

	s.logger.Info("accepting client connections", "addr", transport.Conn.LocalAddr())
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			slogc.Fine(s.logger, "accept error", "err", err)
			return fmt.Errorf("client server quic accept: %w", err)
		}

		serverName := conn.ConnectionState().TLS.ServerName
		switch {
		case netc.IsSubdomain(serverName, "connet.control.relay"):
			rc := &clientConn{
				server: s.controlServer,
				conn:   conn,
				logger: s.controlServer.logger,
			}
			go rc.run(ctx)
		case netc.IsSubdomain(serverName, "connet.relay"):
			go s.directServer.runDirectConn(ctx, conn)
		default:
			rc := &directReserveConn{
				server: s.directServer,
				conn:   conn,
				logger: s.directServer.logger,
			}
			go rc.run(ctx)
		}
	}
}

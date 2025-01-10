package control

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/statusc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Addr *net.UDPAddr
	Cert tls.Certificate

	ClientAuth  ClientAuthenticator
	ClientRestr netc.IPRestriction

	RelayAuth  RelayAuthenticator
	RelayRestr netc.IPRestriction

	Stores Stores

	StatusAddr *net.TCPAddr
	Logger     *slog.Logger
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
		statusAddr: cfg.StatusAddr,
		logger:     cfg.Logger.With("control", cfg.Addr),
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

	return s, nil
}

type Server struct {
	addr    *net.UDPAddr
	tlsConf *tls.Config

	clients *clientServer
	relays  *relayServer

	statusAddr *net.TCPAddr
	logger     *slog.Logger
}

func (s *Server) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return s.relays.run(ctx) })
	g.Go(func() error { return s.clients.run(ctx) })
	g.Go(func() error { return s.runListener(ctx) })
	g.Go(func() error { return s.runStatus(ctx) })

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

func (s *Server) runStatus(ctx context.Context) error {
	if s.statusAddr == nil {
		return nil
	}

	s.logger.Debug("running status server", "addr", s.statusAddr)
	return statusc.Run(ctx, s.statusAddr.String(), s.Status)
}

func (s *Server) Status(ctx context.Context) (Status, error) {
	clients, err := s.getClients()
	if err != nil {
		return Status{}, err
	}

	peers, err := s.getPeers()
	if err != nil {
		return Status{}, err
	}

	relays, err := s.getRelays()
	if err != nil {
		return Status{}, err
	}

	return Status{
		ServerID: s.relays.id,
		Clients:  clients,
		Peers:    peers,
		Relays:   relays,
	}, nil
}

func (s *Server) getClients() ([]statusClient, error) {
	clientMsgs, _, err := s.clients.conns.Snapshot()
	if err != nil {
		return nil, err
	}

	var clients []statusClient
	for _, msg := range clientMsgs {
		clients = append(clients, statusClient{
			ID:   msg.Key.ID,
			Addr: msg.Value.Addr,
		})
	}

	return clients, nil
}

func (s *Server) getPeers() ([]statusPeer, error) {
	peerMsgs, _, err := s.clients.peers.Snapshot()
	if err != nil {
		return nil, err
	}

	var peers []statusPeer
	for _, msg := range peerMsgs {
		peers = append(peers, statusPeer{
			ID:      msg.Key.ID,
			Role:    msg.Key.Role,
			Forward: msg.Key.Forward,
		})
	}

	return peers, nil
}

func (s *Server) getRelays() ([]statusRelay, error) {
	msgs, _, err := s.relays.conns.Snapshot()
	if err != nil {
		return nil, err
	}

	var relays []statusRelay
	for _, msg := range msgs {
		relays = append(relays, statusRelay{
			ID:       msg.Key.ID,
			Hostport: msg.Value.Hostport.String(),
		})
	}

	return relays, nil
}

type Status struct {
	ServerID string         `json:"server_id"`
	Clients  []statusClient `json:"clients"`
	Peers    []statusPeer   `json:"peers"`
	Relays   []statusRelay  `json:"relays"`
}

type statusClient struct {
	ID   ksuid.KSUID `json:"id"`
	Addr string      `json:"addr"`
}

type statusPeer struct {
	ID      ksuid.KSUID   `json:"id"`
	Role    model.Role    `json:"role"`
	Forward model.Forward `json:"forward"`
}

type statusRelay struct {
	ID       ksuid.KSUID `json:"id"`
	Hostport string      `json:"hostport"`
}

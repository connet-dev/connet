package connet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
)

type relayConfig struct {
	addr   *net.UDPAddr
	store  RelayStore
	cert   tls.Certificate
	logger *slog.Logger
}

func newRelayServer(cfg relayConfig) (*relayServer, error) {
	s := &relayServer{
		addr:  cfg.addr,
		store: cfg.store,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cfg.cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			NextProtos:   []string{"connet-relay"},
		},
		logger: cfg.logger.With("relay", cfg.addr),

		destinations: map[Binding]map[ksuid.KSUID]*relayConn{},
	}
	s.tlsConf.GetConfigForClient = s.tlsConfigWithClientCA

	return s, nil
}

type relayServer struct {
	addr    *net.UDPAddr
	store   RelayStore
	tlsConf *tls.Config
	logger  *slog.Logger

	destinations   map[Binding]map[ksuid.KSUID]*relayConn
	destinationsMu sync.RWMutex
}

type relayClientConfigKey [sha256.Size]byte

type relayClientConfig struct {
	cert         *x509.Certificate
	sources      []Binding
	destinations []Binding
}

func (s *relayServer) addDestinations(conn *relayConn) {
	s.destinationsMu.Lock()
	defer s.destinationsMu.Unlock()

	for bind := range conn.auth.Destinations {
		bindDest := s.destinations[bind]
		if bindDest == nil {
			bindDest = map[ksuid.KSUID]*relayConn{}
			s.destinations[bind] = bindDest
		}
		bindDest[conn.id] = conn
	}
}

func (s *relayServer) removeDestinations(conn *relayConn) {
	s.destinationsMu.Lock()
	defer s.destinationsMu.Unlock()

	for bind := range conn.auth.Destinations {
		bindDest := s.destinations[bind]
		delete(bindDest, conn.id)
		if len(bindDest) == 0 {
			delete(s.destinations, bind)
		}
	}
}

func (s *relayServer) findDestinations(bind Binding) []*relayConn {
	s.destinationsMu.RLock()
	defer s.destinationsMu.RUnlock()

	bindDest := s.destinations[bind]
	if bindDest == nil {
		return nil
	}
	return slices.Collect(maps.Values(bindDest))
}

func (s *relayServer) tlsConfigWithClientCA(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	cfg := s.tlsConf.Clone()
	cfg.ClientCAs = s.store.CertificateAuthority()
	return cfg, nil
}

func (s *relayServer) Run(ctx context.Context) error {
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
			if errors.Is(err, quic.ErrServerClosed) {
				s.logger.Info("stopped quic server")
				return nil
			}
			continue
		}
		s.logger.Info("client connected", "local", conn.LocalAddr(), "remote", conn.RemoteAddr())

		rcID := ksuid.New()
		rc := &relayConn{
			id:     rcID,
			server: s,
			conn:   conn,
			logger: s.logger.With("conn-id", rcID),
		}
		go rc.run(ctx)
	}
}

type relayConn struct {
	id     ksuid.KSUID
	server *relayServer
	conn   quic.Connection
	logger *slog.Logger

	auth *RelayAuthentication
}

func (c *relayConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (c *relayConn) runErr(ctx context.Context) error {
	certs := c.conn.ConnectionState().TLS.PeerCertificates
	if auth := c.server.store.Authenticate(certs); auth == nil {
		c.conn.CloseWithError(1, "auth failed")
		return nil
	} else {
		c.auth = auth
	}

	c.server.addDestinations(c)
	defer c.server.removeDestinations(c)

	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go c.runStream(ctx, stream)
	}
}

func (c *relayConn) runStream(ctx context.Context, stream quic.Stream) error {
	defer stream.Close()

	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Connect != nil:
		return c.connect(ctx, stream, NewBindingPB(req.Connect.Binding))
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *relayConn) connect(ctx context.Context, stream quic.Stream, bind Binding) error {
	if !c.auth.AllowSource(bind) {
		err := pb.NewError(pb.Error_DestinationNotFound, "not allowed")
		return pb.Write(stream, &pbc.Response{Error: err})
	}

	dests := c.server.findDestinations(bind)
	for _, dest := range dests {
		if err := c.connectDestination(ctx, stream, bind, dest); err != nil {
			c.logger.Debug("could not dial destination", "err", err)
		} else {
			// connect was success
			return nil
		}
	}

	err := pb.NewError(pb.Error_DestinationNotFound, "could not dial destinations: %d", len(dests))
	return pb.Write(stream, &pbc.Response{Error: err})
}

func (c *relayConn) connectDestination(ctx context.Context, srcStream quic.Stream, bind Binding, dest *relayConn) error {
	dstStream, err := dest.conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Newf("could not open stream: %w", err)
	}

	if err := pb.Write(dstStream, &pbc.Request{
		Connect: &pbc.Request_Connect{
			Binding: bind.AsPB(),
		},
	}); err != nil {
		return kleverr.Newf("could not write request: %w", err)
	}

	if _, err := pbc.ReadResponse(dstStream); err != nil {
		return kleverr.Newf("could not read response: %w", err)
	}

	if err := pb.Write(srcStream, &pbc.Response{}); err != nil {
		return kleverr.Newf("could not write response: %w", err)
	}

	c.logger.Debug("joining conns", "bind", bind)
	err = netc.Join(ctx, srcStream, dstStream)
	c.logger.Debug("disconnected conns", "bind", bind, "err", err)
	return nil
}

func (c *relayConn) unknown(ctx context.Context, stream quic.Stream, req *pbc.Request) error {
	c.logger.Error("unknown request", "req", req)
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(stream, &pbc.Response{Error: err})
}
package relay

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/certc"
	"github.com/connet-dev/connet/pkg/iterc"
	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclientrelay"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/quic-go/quic-go"
)

type clientAuth struct {
	endpoint model.Endpoint
	role     model.Role
	key      model.Key
}

type tlsAuthenticator func(chi *tls.ClientHelloInfo) (*tls.Config, error)
type clientAuthenticator func(serverName string, certs []*x509.Certificate) *clientAuth
type directAuthenticator func(message []byte, authentication []byte) bool

func newClientsServer(cfg Config, tlsAuth tlsAuthenticator, clAuth clientAuthenticator, directAuth directAuthenticator, directCert *certc.Cert) (*clientsServer, error) {
	directTLS, err := directCert.TLSCert()
	if err != nil {
		return nil, fmt.Errorf("direct TLS cert: %w", err)
	}
	directTLSConf := &tls.Config{
		ServerName:   directTLS.Leaf.DNSNames[0],
		Certificates: []tls.Certificate{directTLS},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   iterc.MapVarStrings(model.ConnectRelayV02),
	}

	return &clientsServer{
		tlsConf: &tls.Config{
			NextProtos: iterc.MapVarStrings(model.ConnectRelayV01, model.ConnectRelayV02), // TODO maybe empty?
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				if chi.ServerName == directTLSConf.ServerName {
					return directTLSConf, nil
				}
				return tlsAuth(chi)
			},
		},
		auth:   clAuth,
		direct: directAuth,

		endpoints: map[model.Endpoint]*endpointClients{},

		logger: cfg.Logger.With("server", "relay-clients"),
	}, nil
}

type clientsServer struct {
	tlsConf *tls.Config
	auth    clientAuthenticator
	direct  directAuthenticator

	endpoints   map[model.Endpoint]*endpointClients
	endpointsMu sync.RWMutex

	logger *slog.Logger
}

type endpointClients struct {
	endpoint     model.Endpoint
	destinations map[model.Key]*clientConn
	sources      map[model.Key]*clientConn
	mu           sync.RWMutex
}

func (d *endpointClients) getDestinations() []*clientConn {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return slices.SortedFunc(maps.Values(d.destinations), func(l, r *clientConn) int {
		ld := l.conn.ConnectionStats().SmoothedRTT
		rd := r.conn.ConnectionStats().SmoothedRTT

		return cmp.Compare(ld, rd)
	})
}

func (d *endpointClients) removeDestination(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.destinations, conn.auth.key)

	return d.empty()
}

func (d *endpointClients) removeSource(conn *clientConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.sources, conn.auth.key)

	return d.empty()
}

func (d *endpointClients) empty() bool {
	return (len(d.destinations) + len(d.sources)) == 0
}

func (s *clientsServer) getByEndpoint(endpoint model.Endpoint) *endpointClients {
	s.endpointsMu.RLock()
	dst := s.endpoints[endpoint]
	s.endpointsMu.RUnlock()
	if dst != nil {
		return dst
	}

	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()

	dst = s.endpoints[endpoint]
	if dst != nil {
		return dst
	}

	dst = &endpointClients{
		endpoint:     endpoint,
		destinations: map[model.Key]*clientConn{},
		sources:      map[model.Key]*clientConn{},
	}
	s.endpoints[endpoint] = dst
	return dst
}

func (s *clientsServer) removeByClients(fcs *endpointClients) {
	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()

	fcs.mu.Lock()
	defer fcs.mu.Unlock()

	if fcs.empty() {
		delete(s.endpoints, fcs.endpoint)
	}
}

func (s *clientsServer) addDestination(conn *clientConn) *endpointClients {
	dst := s.getByEndpoint(conn.auth.endpoint)

	dst.mu.Lock()
	defer dst.mu.Unlock()

	dst.destinations[conn.auth.key] = conn

	return dst
}

func (s *clientsServer) removeDestination(fcs *endpointClients, conn *clientConn) {
	if fcs.removeDestination(conn) {
		s.removeByClients(fcs)
	}
}

func (s *clientsServer) addSource(conn *clientConn) *endpointClients {
	target := s.getByEndpoint(conn.auth.endpoint)

	target.mu.Lock()
	defer target.mu.Unlock()

	target.sources[conn.auth.key] = conn

	return target
}

func (s *clientsServer) removeSource(fcs *endpointClients, conn *clientConn) {
	if fcs.removeSource(conn) {
		s.removeByClients(fcs)
	}
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

		rc := &clientConn{
			server: s,
			conn:   conn,
			logger: s.logger,
		}
		go rc.run(ctx)
	}
}

type clientConn struct {
	server *clientsServer
	conn   *quic.Conn
	logger *slog.Logger

	auth *clientAuth
}

func (c *clientConn) run(ctx context.Context) {
	c.logger.Debug("new client connection", "proto", c.conn.ConnectionState().TLS.NegotiatedProtocol, "remote", c.conn.RemoteAddr())
	defer func() {
		if err := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(c.logger, "error closing connection", "err", err)
		}
	}()

	if err := c.runErr(ctx); err != nil {
		c.logger.Debug("error while running client conn", "err", err)
	}
}

var errNotRecognizedClient = errors.New("client not recognized as a destination or a source")

func (c *clientConn) runErr(ctx context.Context) error {
	protocol := model.GetConnectRelayNextProto(c.conn)
	if protocol == model.ConnectRelayV02 {
		if auth, err := c.authenticate(ctx); err != nil {
			return c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "authentication missing")
		} else {
			c.auth = auth
			c.logger = c.logger.With("endpoint", auth.endpoint, "role", auth.role, "key", auth.key)
		}
	} else {
		serverName := c.conn.ConnectionState().TLS.ServerName
		certs := c.conn.ConnectionState().TLS.PeerCertificates
		if auth := c.server.auth(serverName, certs); auth == nil {
			return c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "authentication missing")
		} else {
			c.auth = auth
			c.logger = c.logger.With("endpoint", auth.endpoint, "role", auth.role, "key", auth.key)
		}

		if err := c.check(ctx); err != nil {
			return err
		}
	}

	switch c.auth.role {
	case model.Destination:
		return c.runDestination(ctx)
	case model.Source:
		return c.runSource(ctx)
	default:
		return errNotRecognizedClient
	}
}

type directSignature struct { // TODO go through protobuf? share globally?
	Endpoint    model.Endpoint `json:"endpoint"`
	Role        model.Role     `json:"role"`
	Certificate []byte         `json:"certificate"`
}

func (c *clientConn) authenticate(ctx context.Context) (*clientAuth, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("client auth stream: %w", err)
	}
	defer func() {
		if err := authStream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing auth stream", "err", err)
		}
	}()

	req := &pbclientrelay.AuthenticateReq{}
	if err := proto.Read(authStream, req); err != nil {
		return nil, fmt.Errorf("client auth read: %w", err)
	}

	sig := directSignature{model.EndpointFromPB(req.Endpoint), model.RoleFromPB(req.Role), c.conn.ConnectionState().TLS.PeerCertificates[0].Raw}
	if signatureData, err := json.Marshal(sig); err != nil {
		return nil, fmt.Errorf("signature data error: %w", err)
	} else if valid := c.server.direct(signatureData, req.Authentication); !valid {
		return nil, fmt.Errorf("cannot authenticate: %w", err)
	}

	if err := proto.Write(authStream, &pbclientrelay.AuthenticateResp{}); err != nil {
		return nil, fmt.Errorf("client auth write: %w", err)
	}

	key := model.NewKey(c.conn.ConnectionState().TLS.PeerCertificates[0])
	c.logger.Debug("authentication completed", "remote", c.conn.RemoteAddr(), "build", req.BuildVersion)
	return &clientAuth{sig.Endpoint, sig.Role, key}, nil
}

func (c *clientConn) check(ctx context.Context) error {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept client stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing check client stream", "err", err)
		}
	}()

	if _, err := pbconnect.ReadRequest(stream); err != nil {
		return fmt.Errorf("read client stream: %w", err)
	} else if err := proto.Write(stream, &pbconnect.Response{}); err != nil {
		return fmt.Errorf("write client stream: %w", err)
	}

	return nil
}

func (c *clientConn) runDestination(ctx context.Context) error {
	fcs := c.server.addDestination(c)
	defer c.server.removeDestination(fcs, c)

	return quicc.WaitLogRTTStats(ctx, c.conn, c.logger)
}

func (c *clientConn) runSource(ctx context.Context) error {
	fcs := c.server.addSource(c)
	defer c.server.removeSource(fcs, c)

	g := reliable.NewGroup(ctx)

	g.Go(func(ctx context.Context) error {
		return quicc.WaitLogRTTStats(ctx, c.conn, c.logger)
	})

	g.Go(func(ctx context.Context) error {
		for {
			stream, err := c.conn.AcceptStream(ctx)
			if err != nil {
				return fmt.Errorf("accept source stream: %w", err)
			}
			go c.runSourceStream(ctx, stream, fcs)
		}
	})

	return g.Wait()
}

func (c *clientConn) runSourceStream(ctx context.Context, stream *quic.Stream, fcs *endpointClients) {
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing source stream", "err", err)
		}
	}()

	if err := c.runSourceStreamErr(ctx, stream, fcs); err != nil {
		c.logger.Debug("error while running source", "err", err)
	}
}

func (c *clientConn) runSourceStreamErr(ctx context.Context, stream *quic.Stream, fcs *endpointClients) error {
	req, err := pbconnect.ReadRequest(stream)
	if err != nil {
		return fmt.Errorf("source stream read: %w", err)
	}

	switch {
	case req.Connect != nil:
		return c.connect(ctx, stream, fcs, req)
	default:
		return c.unknown(ctx, stream, req)
	}
}

func (c *clientConn) connect(ctx context.Context, stream *quic.Stream, fcs *endpointClients, req *pbconnect.Request) error {
	dests := fcs.getDestinations()
	if len(dests) == 0 {
		err := pberror.NewError(pberror.Code_DestinationNotFound, "could not find destination")
		return proto.Write(stream, &pbconnect.Response{Error: err})
	}

	var pberrs []string
	for _, dest := range dests {
		if err := c.connectDestination(ctx, stream, dest, req); err != nil {
			if pberr := pberror.GetError(err); pberr != nil {
				pberrs = append(pberrs, pberr.Error())
			}
			c.logger.Debug("could not dial destination", "err", err)
		} else {
			// connect was success
			return nil
		}
	}

	err := pberror.NewError(pberror.Code_DestinationDialFailed, "could not dial destinations: %v", pberrs)
	return proto.Write(stream, &pbconnect.Response{Error: err})
}

func (c *clientConn) connectDestination(ctx context.Context, srcStream *quic.Stream, dest *clientConn, req *pbconnect.Request) error {
	dstStream, err := dest.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("destination open stream: %w", err)
	}

	if err := proto.Write(dstStream, req); err != nil {
		return fmt.Errorf("destination write request: %w", err)
	}

	resp, err := pbconnect.ReadResponse(dstStream)
	if err != nil {
		return fmt.Errorf("destination read response: %w", err)
	}

	if err := proto.Write(srcStream, resp); err != nil {
		return fmt.Errorf("source write response: %w", err)
	}

	c.logger.Debug("joining conns")
	err = netc.Join(srcStream, dstStream)
	c.logger.Debug("disconnected conns", "err", err)
	return nil
}

func (c *clientConn) unknown(_ context.Context, stream *quic.Stream, req *pbconnect.Request) error {
	c.logger.Error("unknown request", "req", req)
	err := pberror.NewError(pberror.Code_RequestUnknown, "unknown request: %v", req)
	return proto.Write(stream, &pbconnect.Response{Error: err})
}

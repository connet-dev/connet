package relay

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclientrelay"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/slogc"
	"github.com/quic-go/quic-go"
)

type clientsDirectServer struct {
	rootCert *certc.Cert

	peerServers   map[string]*directPeerServer
	peerServersMu sync.RWMutex

	logger *slog.Logger
}

func (s *clientsDirectServer) runDirectConn(ctx context.Context, conn *quic.Conn) {
	s.logger.Debug("new client connection", "server", conn.ConnectionState().TLS.ServerName, "remote", conn.RemoteAddr())

	s.peerServersMu.RLock()
	srv := s.peerServers[conn.ConnectionState().TLS.ServerName]
	s.peerServersMu.RUnlock()

	if srv == nil {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "connection closed"); err != nil {
			slogc.Fine(s.logger, "error closing connection", "err", err)
		}
		return
	}

	srv.runRemote(ctx, conn)
}

type directReserveConn struct {
	server *clientsDirectServer
	conn   *quic.Conn
	logger *slog.Logger

	directAuth
}

type directAuth struct {
	id       string
	metadata string
}

func (c *directReserveConn) run(ctx context.Context) {
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

func (c *directReserveConn) runErr(ctx context.Context) error {
	if auth, err := c.authenticate(ctx); err != nil {
		if perr := pberror.GetError(err); perr != nil {
			cerr := c.conn.CloseWithError(quic.ApplicationErrorCode(perr.Code), perr.Message)
			err = errors.Join(perr, cerr)
		} else {
			cerr := c.conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "Error while authenticating")
			err = errors.Join(err, cerr)
		}
		return err
	} else {
		c.directAuth = *auth
		c.logger = c.logger.With("client-id", c.id)
	}

	c.logger.Info("client connected", "addr", c.conn.RemoteAddr(), "metadata", c.metadata)
	defer c.logger.Info("client disconnected", "addr", c.conn.RemoteAddr(), "metadata", c.metadata)
	// TODO client connection tracking
	// connected + defer disconnected

	return c.reserve(ctx)
}

func (c *directReserveConn) authenticate(ctx context.Context) (*directAuth, error) {
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

	// TODO checks

	// origin, err := pbmodel.AddrPortFromNet(c.conn.RemoteAddr())
	// if err != nil {
	// 	err := pberror.NewError(pberror.Code_AuthenticationFailed, "cannot resolve origin: %v", err)
	// 	if err := proto.Write(authStream, &pbclientrelay.AuthenticateResp{Error: err}); err != nil {
	// 		return nil, fmt.Errorf("client auth err write: %w", err)
	// 	}
	// 	return nil, fmt.Errorf("client addr port from net: %w", err)
	// }

	if err := proto.Write(authStream, &pbclientrelay.AuthenticateResp{}); err != nil {
		return nil, fmt.Errorf("client auth write: %w", err)
	}

	c.logger.Debug("authentication completed", "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr(), "build", req.BuildVersion)
	return &directAuth{req.ClientId, req.Metadata}, nil
}

func (c *directReserveConn) reserve(ctx context.Context) error {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("client reserve stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(c.logger, "error closing reserve stream", "err", err)
		}
	}()

	req := &pbclientrelay.ReserveReq{}
	if err := proto.Read(stream, req); err != nil {
		return fmt.Errorf("client req read: %w", err)
	}

	srv, err := newDirectPeerServer(c, req.Peers)
	if err != nil {
		err := pberror.NewError(pberror.Code_RelayReserveFailed, "create server: %v", err)
		if err := proto.Write(stream, &pbclientrelay.ReserveResp{Error: err}); err != nil {
			return fmt.Errorf("client create server err write: %w", err)
		}
		return fmt.Errorf("client create server: %w", err)
	}

	c.server.peerServersMu.Lock()
	c.server.peerServers[srv.serverName] = srv
	c.server.peerServersMu.Unlock()
	defer func() {
		c.server.peerServersMu.Lock()
		delete(c.server.peerServers, srv.serverName)
		c.server.peerServersMu.Unlock()
	}()

	if err := proto.Write(stream, &pbclientrelay.ReserveResp{
		ServerCertificate: srv.serverCert.Raw(),
	}); err != nil {
		return fmt.Errorf("client resp write: %w", err)
	}

	return srv.runReserveErr(ctx, stream)
}

type directPeerServer struct {
	localConn *directReserveConn

	serverName string
	serverCert *certc.Cert
	serverTLS  *tls.Config

	expectClients   map[string]model.Key
	expectClientsMu sync.RWMutex
	tlsConf         atomic.Pointer[tls.Config]

	remoteConns   map[model.Key]*quic.Conn
	remoteConnsMu sync.RWMutex

	logger *slog.Logger
}

func newDirectPeerServer(conn *directReserveConn, peers []*pbclientrelay.Peer) (*directPeerServer, error) {
	serverName := netc.GenDomainName("connet.relay")
	serverCert, err := conn.server.rootCert.NewServer(certc.CertOpts{
		Domains: []string{serverName},
	})
	if err != nil {
		return nil, fmt.Errorf("cannot create server cert: %w", err)
	}
	serverTLSCert, err := serverCert.TLSCert()
	if err != nil {
		return nil, fmt.Errorf("cannot get server tls cert: %w", err)
	}

	s := &directPeerServer{
		localConn: conn,

		serverName: serverName,
		serverCert: serverCert,
		serverTLS: &tls.Config{
			ServerName:   serverName,
			Certificates: []tls.Certificate{serverTLSCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			NextProtos:   model.ConnectRelayDirectNextProtos,
		},

		remoteConns: map[model.Key]*quic.Conn{},

		logger: conn.logger.With("peer-server", serverName),
	}

	if err := s.update(peers); err != nil {
		return nil, fmt.Errorf("update client certs: %w", err)
	}

	return s, nil
}

func (s *directPeerServer) runReserveErr(ctx context.Context, stream *quic.Stream) error {
	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(stream))

	g.Go(func(ctx context.Context) error {
		for {
			req := &pbclientrelay.ReserveReq{}
			if err := proto.Read(stream, req); err != nil {
				return fmt.Errorf("client req read: %w", err)
			}

			if err := s.update(req.Peers); err != nil {
				err := pberror.NewError(pberror.Code_RelayReserveFailed, "update server: %v", err)
				if err := proto.Write(stream, &pbclientrelay.ReserveResp{Error: err}); err != nil {
					return fmt.Errorf("client update server err write: %w", err)
				}
				return fmt.Errorf("client update server: %w", err)
			}

			if err := proto.Write(stream, &pbclientrelay.ReserveResp{
				ServerCertificate: s.serverCert.Raw(),
			}); err != nil {
				return fmt.Errorf("client resp write: %w", err)
			}
		}
	})

	g.Go(func(ctx context.Context) error {
		return s.runSource(ctx)
	})

	return g.Wait()
}

func (s *directPeerServer) update(peers []*pbclientrelay.Peer) error {
	clients := map[string]model.Key{}
	clientCAs := x509.NewCertPool()
	for _, peer := range peers {
		cert, err := x509.ParseCertificate(peer.ClientCertificate)
		if err != nil {
			return fmt.Errorf("cannot parse certificate for %s: %w", peer.Id, err)
		}

		clients[peer.Id] = model.NewKey(cert)
		clientCAs.AddCert(cert)
	}

	s.expectClientsMu.Lock()
	s.expectClients = clients
	s.expectClientsMu.Unlock()

	// TODO optimize
	s.serverTLS.ClientCAs = clientCAs
	s.tlsConf.Store(s.serverTLS.Clone())

	return nil
}

func (s *directPeerServer) runSource(ctx context.Context) error {
	for {
		stream, err := s.localConn.conn.AcceptStream(ctx)
		if err != nil {
			return fmt.Errorf("could not accept source stream: %w", err)
		}
		go s.runSourceStream(ctx, stream)
	}
}

func (s *directPeerServer) runSourceStream(ctx context.Context, stream *quic.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(s.logger, "error closing source stream", "err", err)
		}
	}()

	if err := s.runSourceStreamErr(ctx, stream); err != nil {
		s.logger.Debug("error while running source", "err", err)
	}
}

func (d *directPeerServer) getRemoteConns() []*quic.Conn {
	d.remoteConnsMu.RLock()
	defer d.remoteConnsMu.RUnlock()

	return slices.SortedFunc(maps.Values(d.remoteConns), func(l, r *quic.Conn) int {
		ld := l.ConnectionStats().SmoothedRTT
		rd := r.ConnectionStats().SmoothedRTT

		return cmp.Compare(ld, rd)
	})
}

func (s *directPeerServer) runSourceStreamErr(ctx context.Context, stream *quic.Stream) error {
	req, err := pbconnect.ReadRequest(stream)
	if err != nil {
		return fmt.Errorf("source stream read: %w", err)
	}

	switch {
	case req.Connect != nil:
		return s.connectSources(ctx, stream, req)
	default:
		return s.unknown(ctx, stream, req)
	}
}

func (s *directPeerServer) connectSources(ctx context.Context, stream *quic.Stream, req *pbconnect.Request) error {
	dests := s.getRemoteConns()
	if len(dests) == 0 {
		err := pberror.NewError(pberror.Code_DestinationNotFound, "could not find destination")
		return proto.Write(stream, &pbconnect.Response{Error: err})
	}

	var pberrs []string
	for _, dest := range dests {
		if err := s.connectSource(ctx, stream, dest, req); err != nil {
			if pberr := pberror.GetError(err); pberr != nil {
				pberrs = append(pberrs, pberr.Error())
			}
			s.logger.Debug("could not dial destination", "err", err)
		} else {
			// connect was success
			return nil
		}
	}

	err := pberror.NewError(pberror.Code_DestinationDialFailed, "could not dial destinations: %v", pberrs)
	return proto.Write(stream, &pbconnect.Response{Error: err})
}

func (s *directPeerServer) connectSource(ctx context.Context, srcStream *quic.Stream, dst *quic.Conn, req *pbconnect.Request) error {
	dstStream, err := dst.OpenStreamSync(ctx)
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

	s.logger.Debug("joining conns")
	err = netc.Join(srcStream, dstStream)
	s.logger.Debug("disconnected conns", "err", err)
	return nil
}

func (s *directPeerServer) runRemote(ctx context.Context, conn *quic.Conn) {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(s.logger, "error closing connection", "err", err)
		}
	}()

	if err := s.runRemoteErr(ctx, conn); err != nil {
		s.logger.Debug("error while running client conn", "err", err)
	}
}

func (s *directPeerServer) runRemoteErr(ctx context.Context, conn *quic.Conn) error {
	if err := s.check(ctx, conn); err != nil {
		return err
	}

	key := model.NewKey(conn.ConnectionState().TLS.PeerCertificates[0])
	s.remoteConnsMu.Lock()
	s.remoteConns[key] = conn
	s.remoteConnsMu.Unlock()
	defer func() {
		s.remoteConnsMu.Lock()
		delete(s.remoteConns, key)
		s.remoteConnsMu.Unlock()
	}()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go s.runDestinationStream(ctx, stream)
	}
}

func (s *directPeerServer) check(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept client stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(s.logger, "error closing check client stream", "err", err)
		}
	}()

	if _, err := pbconnect.ReadRequest(stream); err != nil {
		return fmt.Errorf("read client stream: %w", err)
	} else if err := proto.Write(stream, &pbconnect.Response{}); err != nil {
		return fmt.Errorf("write client stream: %w", err)
	}

	return nil
}

func (s *directPeerServer) runDestinationStream(ctx context.Context, stream *quic.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(s.logger, "error closing source stream", "err", err)
		}
	}()

	if err := s.runDestinationStreamErr(ctx, stream); err != nil {
		s.logger.Debug("error while running source", "err", err)
	}
}

func (s *directPeerServer) runDestinationStreamErr(ctx context.Context, stream *quic.Stream) error {
	req, err := pbconnect.ReadRequest(stream)
	if err != nil {
		return fmt.Errorf("source stream read: %w", err)
	}

	switch {
	case req.Connect != nil:
		return s.connectDestination(ctx, stream, req)
	default:
		return s.unknown(ctx, stream, req)
	}
}

func (s *directPeerServer) connectDestination(ctx context.Context, stream *quic.Stream, req *pbconnect.Request) error {
	dstStream, err := s.localConn.conn.OpenStreamSync(ctx)
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

	if err := proto.Write(stream, resp); err != nil {
		return fmt.Errorf("source write response: %w", err)
	}

	s.logger.Debug("joining conns")
	err = netc.Join(stream, dstStream)
	s.logger.Debug("disconnected conns", "err", err)
	return nil
}

func (s *directPeerServer) unknown(_ context.Context, stream *quic.Stream, req *pbconnect.Request) error {
	s.logger.Error("unknown request", "req", req)
	err := pberror.NewError(pberror.Code_RequestUnknown, "unknown request: %v", req)
	return proto.Write(stream, &pbconnect.Response{Error: err})
}

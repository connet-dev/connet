package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
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

func (s *clientsServer) runDirectConn(ctx context.Context, conn *quic.Conn) {
	s.logger.Info("new client connected", "SNI", conn.ConnectionState().TLS.ServerName, "remote", conn.RemoteAddr())

	s.peerServersMu.RLock()
	srv := s.peerServers[conn.ConnectionState().TLS.ServerName]
	s.peerServersMu.RUnlock()

	if srv == nil {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_AuthenticationFailed), "connection closed"); err != nil {
			slogc.Fine(s.logger, "error closing connection", "err", err)
		}
		return
	}

	srv.run(ctx, conn)
}

type directReserveConn struct {
	server *clientsServer
	conn   *quic.Conn
	logger *slog.Logger

	directAuth
}

type directAuth struct {
	id string
}

func (c *directReserveConn) run(ctx context.Context) {
	c.logger.Info("new client connected", "proto", c.conn.ConnectionState().TLS.NegotiatedProtocol, "remote", c.conn.RemoteAddr())
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
	return &directAuth{id: req.ClientId}, nil
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
		// TODO notify client
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

	g := reliable.NewGroup(ctx)
	g.Go(quicc.CancelStream(stream))

	g.Go(func(ctx context.Context) error {
		for {
			req := &pbclientrelay.ReserveReq{}
			if err := proto.Read(stream, req); err != nil {
				return fmt.Errorf("client req read: %w", err)
			}

			if err := srv.update(req.Peers); err != nil {
				// TODO notify client
				return fmt.Errorf("client update server: %w", err)
			}

			if err := proto.Write(stream, &pbclientrelay.ReserveResp{
				ServerCertificate: srv.serverCert.Raw(),
			}); err != nil {
				return fmt.Errorf("client resp write: %w", err)
			}
		}
	})

	return g.Wait()
}

type directPeerServer struct {
	conn *directReserveConn

	serverName string
	serverCert *certc.Cert
	serverTLS  *tls.Config

	tlsConf atomic.Pointer[tls.Config]

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
		conn: conn,

		serverName: serverName,
		serverCert: serverCert,
		serverTLS: &tls.Config{
			ServerName:   serverName,
			Certificates: []tls.Certificate{serverTLSCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			NextProtos:   model.ConnectRelayNextProtos,
		},

		logger: conn.logger.With("peer-server", serverName),
	}

	if err := s.update(peers); err != nil {
		return nil, fmt.Errorf("update client certs: %w", err)
	}

	return s, nil
}

func (s *directPeerServer) update(peers []*pbclientrelay.Peer) error {
	clientCAs := x509.NewCertPool()
	for _, peer := range peers {
		cert, err := x509.ParseCertificate(peer.ClientCertificate)
		if err != nil {
			return fmt.Errorf("cannot parse certificate for %s: %w", peer.Id, err)
		}
		clientCAs.AddCert(cert)
	}

	// TODO optimize
	s.serverTLS.ClientCAs = clientCAs
	s.tlsConf.Store(s.serverTLS.Clone())

	return nil
}

func (s *directPeerServer) run(ctx context.Context, conn *quic.Conn) {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_Unknown), "connection closed"); err != nil {
			slogc.Fine(s.logger, "error closing connection", "err", err)
		}
	}()

	if err := s.runErr(ctx, conn); err != nil {
		s.logger.Debug("error while running client conn", "err", err)
	}
}

func (s *directPeerServer) runErr(ctx context.Context, conn *quic.Conn) error {
	if err := s.check(ctx, conn); err != nil {
		return err
	}

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go s.runStream(ctx, stream)
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

func (s *directPeerServer) runStream(ctx context.Context, stream *quic.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(s.logger, "error closing source stream", "err", err)
		}
	}()

	if err := s.runStreamErr(ctx, stream); err != nil {
		s.logger.Debug("error while running source", "err", err)
	}
}

func (s *directPeerServer) runStreamErr(ctx context.Context, stream *quic.Stream) error {
	req, err := pbconnect.ReadRequest(stream)
	if err != nil {
		return fmt.Errorf("source stream read: %w", err)
	}

	switch {
	case req.Connect != nil:
		return s.connect(ctx, stream, req)
	default:
		return s.unknown(ctx, stream, req)
	}
}

func (s *directPeerServer) connect(ctx context.Context, stream *quic.Stream, req *pbconnect.Request) error {
	dstStream, err := s.conn.conn.OpenStreamSync(ctx)
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

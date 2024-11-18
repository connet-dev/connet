package connet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/keihaya-com/connet/authc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/segmentio/ksuid"
	"golang.org/x/sync/errgroup"
)

type controlConfig struct {
	addr   *net.UDPAddr
	auth   authc.Authenticator
	store  RelayStoreManager
	cert   tls.Certificate
	logger *slog.Logger
}

func newControlServer(cfg controlConfig) (*controlServer, error) {
	return &controlServer{
		addr:   cfg.addr,
		auth:   cfg.auth,
		logger: cfg.logger.With("control", cfg.addr),
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cfg.cert},
			NextProtos:   []string{"connet"},
		},

		whispers: NewWhispers(),
	}, nil
}

type controlServer struct {
	addr    *net.UDPAddr
	auth    authc.Authenticator
	store   RelayStoreManager
	tlsConf *tls.Config
	logger  *slog.Logger

	whispers *Whispers
}

type controlBinding struct {
	destinations map[[sha256.Size]byte]*controlDestination
	sources      map[[sha256.Size]byte]*controlSource
	mu           sync.Mutex
}

type controlDestination struct {
	cert   *x509.Certificate
	addr   *pb.AddrPort
	notify chan controlDestinationNotify
}

type controlDestinationNotify struct {
	certs []*x509.Certificate
}

type controlSource struct {
	cert   *x509.Certificate
	notify chan []*x509.Certificate
}

type controlSourceNotify struct {
	certs []*x509.Certificate
	addrs []*pb.AddrPort
}

func (b *controlBinding) destination(cert *x509.Certificate, addr *pb.AddrPort) chan controlDestinationNotify {
	b.mu.Lock()
	defer b.mu.Unlock()

	dst := &controlDestination{
		cert:   cert,
		addr:   addr,
		notify: make(chan controlDestinationNotify, 1),
	}
	b.destinations[sha256.Sum256(cert.Raw)] = dst

	var sources []*x509.Certificate
	for _, src := range b.sources {
		sources = append(sources, src.cert)
	}
	dst.notify <- controlDestinationNotify{sources}

	return dst.notify
}

func (b *controlBinding) undestination(cert *x509.Certificate) {
	b.mu.Lock()
	defer b.mu.Unlock()

	hash := sha256.Sum256(cert.Raw)
	dst := b.destinations[hash]
	close(dst.notify)

	delete(b.destinations, hash)
}

func (b *controlBinding) source(cert *x509.Certificate) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	return nil
}

func (s *controlServer) Run(ctx context.Context) error {
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

		cID := ksuid.New()
		cc := &controlConn{
			id:     cID,
			server: s,
			conn:   conn,
			logger: s.logger.With("conn-id", cID),
		}
		go cc.run(ctx)
	}
}

type controlConn struct {
	id     ksuid.KSUID
	server *controlServer
	conn   quic.Connection
	logger *slog.Logger

	auth authc.Authentication
}

func (c *controlConn) run(ctx context.Context) {
	defer c.conn.CloseWithError(0, "done")

	if err := c.runErr(ctx); err != nil {
		c.logger.Warn("error while running", "err", err)
	}
}

func (c *controlConn) runErr(ctx context.Context) error {
	if auth, err := c.authenticate(ctx); err != nil {
		c.conn.CloseWithError(1, "auth failed")
		return kleverr.Ret(err)
	} else {
		c.auth = auth
	}

	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			return err
		}

		sID := ksuid.New()
		cs := &controlStream{
			id:     sID,
			conn:   c,
			stream: stream,
			logger: c.logger.With("stream-id", sID),
		}
		go cs.run(ctx)
	}
}

func (c *controlConn) authenticate(ctx context.Context) (authc.Authentication, error) {
	c.logger.Debug("waiting for authentication")
	authStream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return retAuth(err)
	}
	defer authStream.Close()

	req := &pbs.Authenticate{}
	if err := pb.Read(authStream, req); err != nil {
		return retAuth(err)
	}

	auth, err := c.server.auth.Authenticate(req.Token)
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "Invalid or unknown token")
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retAuth(err)
		}
		return retAuth(err)
	}

	origin, err := pb.AddrPortFromNet(c.conn.RemoteAddr())
	if err != nil {
		err := pb.NewError(pb.Error_AuthenticationFailed, "cannot resolve origin: %v", err)
		if err := pb.Write(authStream, &pbs.AuthenticateResp{Error: err}); err != nil {
			return retAuth(err)
		}
		return retAuth(err)
	}

	if err := pb.Write(authStream, &pbs.AuthenticateResp{
		Public: origin,
	}); err != nil {
		return retAuth(err)
	}

	c.logger.Debug("authentication completed", "realms", auth.Realms, "local", c.conn.LocalAddr(), "remote", c.conn.RemoteAddr())
	return auth, nil
}

type controlStream struct {
	id     ksuid.KSUID
	conn   *controlConn
	stream quic.Stream
	logger *slog.Logger
}

func (s *controlStream) run(ctx context.Context) {
	defer s.stream.Close()

	if err := s.runErr(ctx); err != nil {
		s.logger.Warn("error while running", "err", err)
	}
}

func (s *controlStream) runErr(ctx context.Context) error {
	req, err := pbs.ReadRequest(s.stream)
	if err != nil {
		return err
	}

	switch {
	case req.Relay != nil:
		return s.relay(ctx, req.Relay)
	case req.Destination != nil:
		return s.destination(ctx, req.Destination)
	case req.Source != nil:
		return s.source(ctx, req.Source)
	default:
		return s.unknown(ctx, req)
	}
}

func (s *controlStream) relay(ctx context.Context, req *pbs.Request_Relay) error {
	cert, err := x509.ParseCertificate(req.Certificate)
	if err != nil {
		// TODO reply
		return kleverr.Ret(err)
	}

	var destinations []Binding
	for _, bind := range req.Destinations {
		destinations = append(destinations, NewBindingPB(bind))
	}
	var sources []Binding
	for _, bind := range req.Sources {
		sources = append(sources, NewBindingPB(bind))
	}

	s.conn.server.store.Add(cert, destinations, sources)

	addrs, retry := s.conn.server.store.Relays()
	if err := pb.Write(s.stream, &pbs.Response{
		Relay: &pbs.Response_Relay{
			Addresses: pb.AsAddrPorts(addrs),
		},
	}); err != nil {
		return kleverr.Ret(err)
	}

	for retry {
		addrs, retry = s.conn.server.store.Relays()
		if err := pb.Write(s.stream, &pbs.Response{
			Relay: &pbs.Response_Relay{
				Addresses: pb.AsAddrPorts(addrs),
			},
		}); err != nil {
			return kleverr.Ret(err)
		}
	}

	return nil
}

func (s *controlStream) destination(ctx context.Context, req *pbs.Request_Destination) error {
	cert, err := x509.ParseCertificate(req.Certificate)
	if err != nil {
		respErr := pb.NewError(pb.Error_Unknown, "cannot parse certificate: %v", err)
		return pb.Write(s.stream, &pbs.Response{Error: respErr})
	}

	w := s.conn.server.whispers.For(NewBindingPB(req.Binding))

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		w.AddDestination(cert, pb.AsNetips(req.DirectAddresses), pb.AsNetips(req.RelayAddresses))
		defer func() {
			w.RemoveDestination(cert)
		}()

		for {
			req, err := pbs.ReadRequest(s.stream)
			if err != nil {
				return err
			}
			if req.Destination == nil {
				respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
				if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			newCert, err := x509.ParseCertificate(req.Destination.Certificate)
			if err != nil {
				respErr := pb.NewError(pb.Error_Unknown, "cannot parse certificate: %v", err)
				if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			w.RemoveDestination(cert)
			w.AddDestination(newCert, pb.AsNetips(req.Destination.DirectAddresses), pb.AsNetips(req.Destination.RelayAddresses))
			cert = newCert
		}
	})

	g.Go(func() error {
		for {
			certs := w.Sources()
			var certData [][]byte
			for _, cert := range certs {
				certData = append(certData, cert.Raw)
			}
			if err := pb.Write(s.stream, &pbs.Response{
				Destination: &pbs.Response_Destination{
					Certificates: certData,
				},
			}); err != nil {
				return kleverr.Ret(err)
			}
		}
	})

	return g.Wait()
}

func (s *controlStream) source(ctx context.Context, req *pbs.Request_Source) error {
	cert, err := x509.ParseCertificate(req.Certificate)
	if err != nil {
		respErr := pb.NewError(pb.Error_Unknown, "cannot parse certificate: %v", err)
		return pb.Write(s.stream, &pbs.Response{Error: respErr})
	}

	w := s.conn.server.whispers.For(NewBindingPB(req.Binding))

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		w.AddSource(cert)
		defer func() {
			w.RemoveSource(cert)
		}()

		for {
			req, err := pbs.ReadRequest(s.stream)
			if err != nil {
				return err
			}
			if req.Source == nil {
				respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
				if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}

			newCert, err := x509.ParseCertificate(req.Source.Certificate)
			if err != nil {
				respErr := pb.NewError(pb.Error_Unknown, "cannot parse certificate: %v", err)
				if err := pb.Write(s.stream, &pbs.Response{Error: respErr}); err != nil {
					return kleverr.Ret(err)
				}
				return respErr
			}
			w.RemoveSource(cert)
			w.AddSource(newCert)
			cert = newCert
		}
	})

	g.Go(func() error {
		for {
			update := w.Destinations()

			resp := &pbs.Response_Source{
				Relays: pb.AsAddrPorts(update.Relays),
			}
			for _, cl := range update.Clients {
				resp.Clients = append(resp.Clients, &pbs.Response_Source_Client{
					Certificate: cl.Certificate.Raw,
					Addresses:   pb.AsAddrPorts(cl.Addresses),
				})
			}

			if err := pb.Write(s.stream, &pbs.Response{
				Source: resp,
			}); err != nil {
				return kleverr.Ret(err)
			}
		}
	})

	return g.Wait()
}

func (s *controlStream) unknown(ctx context.Context, req *pbs.Request) error {
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	return pb.Write(s.stream, &pbc.Response{Error: err})
}

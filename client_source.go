package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"net"
	"sync"
	"time"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
)

type clientSourceServer struct {
	addr      string
	fwd       model.Forward
	transport *quic.Transport
	cert      tls.Certificate
	relayCAs  *x509.CertPool
	logger    *slog.Logger

	directRoutes map[string]*x509.CertPool
	relayRoutes  map[string]struct{}
	routesMu     sync.RWMutex

	activeRoute   quic.Connection
	activeRouteMu sync.RWMutex
}

func (s *clientSourceServer) setRoutes(direct map[string]*x509.Certificate, relays map[string]struct{}) {
	newDirect := map[string]*x509.CertPool{}
	for addr, cert := range direct {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		newDirect[addr] = pool
	}

	newRelay := maps.Clone(relays)

	s.routesMu.Lock()
	defer s.routesMu.Unlock()

	s.directRoutes = newDirect
	s.relayRoutes = newRelay
}

func (s *clientSourceServer) getDirectRoutes() map[string]*x509.CertPool {
	s.routesMu.RLock()
	defer s.routesMu.RUnlock()

	return maps.Clone(s.directRoutes)
}

func (s *clientSourceServer) getRelayRoutes() map[string]struct{} {
	s.routesMu.RLock()
	defer s.routesMu.RUnlock()

	return maps.Clone(s.relayRoutes)
}

func (s *clientSourceServer) findRoute(ctx context.Context) (quic.Stream, error) {
	s.activeRouteMu.RLock()
	activeRoute := s.activeRoute
	s.activeRouteMu.RUnlock()

	if activeRoute != nil {
		stream, err := activeRoute.OpenStreamSync(ctx)
		if err == nil {
			return stream, nil
		}
		s.logger.Debug("cannot reuse active route", "err", err)
	}

	s.activeRouteMu.Lock()
	defer s.activeRouteMu.Unlock()

	if s.activeRoute == activeRoute {
		s.activeRoute = nil
	} else if s.activeRoute != nil {
		stream, err := s.activeRoute.OpenStreamSync(ctx)
		if err == nil {
			return stream, nil
		}
		s.activeRoute = nil
	}

	// try direct routes first
	for addr, cert := range s.getDirectRoutes() {
		conn, err := s.dialDirect(ctx, addr, cert)
		if err != nil {
			s.logger.Debug("failed to direct dial", "addr", addr, "err", err)
			continue
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			s.logger.Debug("failed to direct open stream", "addr", addr, "err", err)
			continue
		}
		s.activeRoute = conn
		return stream, nil
	}

	// now try the relays
	for hostport := range s.getRelayRoutes() {
		conn, err := s.dialRelay(ctx, hostport)
		if err != nil {
			s.logger.Debug("failed to relay dial", "hostport", hostport, "err", err)
			continue
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			s.logger.Debug("failed to relay open stream", "hostport", hostport, "err", err)
			continue
		}
		s.activeRoute = conn
		return stream, nil
	}

	return nil, kleverr.New("unable to dial any route")
}

func (s *clientSourceServer) dialDirect(ctx context.Context, hostport string, pool *x509.CertPool) (quic.Connection, error) {
	addr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	return s.transport.Dial(ctx, addr, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		RootCAs:      pool,
		ServerName:   "connet-direct",
		NextProtos:   []string{"connet-direct"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
}

func (s *clientSourceServer) dialRelay(ctx context.Context, hostport string) (quic.Connection, error) {
	addr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	return s.transport.Dial(ctx, addr, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		RootCAs:      s.relayCAs,
		ServerName:   host,
		NextProtos:   []string{"connet-relay"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
}

func (s *clientSourceServer) run(ctx context.Context) error {
	s.logger.Debug("listening for conns")
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return kleverr.Ret(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return kleverr.Ret(err)
		}

		go s.runConn(ctx, conn)
	}
}

func (s *clientSourceServer) runConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	if err := s.runConnErr(ctx, conn); err != nil {
		s.logger.Warn("error handling conn", "err", err)
	}
}

func (s *clientSourceServer) runConnErr(ctx context.Context, conn net.Conn) error {
	stream, err := s.findRoute(ctx)
	if err != nil {
		return kleverr.Newf("could not find route: %w", err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbc.Request{
		Connect: &pbc.Request_Connect{
			To: s.fwd.PB(),
		},
	}); err != nil {
		return kleverr.Newf("could not write request: %w", err)
	}

	resp, err := pbc.ReadResponse(stream)
	if err != nil {
		return kleverr.Newf("could not read response: %w", err)
	}

	s.logger.Debug("joining to server", "connect", resp)
	err = netc.Join(ctx, conn, stream)
	s.logger.Debug("disconnected to server", "err", err)

	return nil
}

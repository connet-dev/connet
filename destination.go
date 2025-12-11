package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/connet-dev/connet/cryptoc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/reliable"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

// DestinationConfig structure represents destination configuration.
type DestinationConfig struct {
	Endpoint         model.Endpoint
	Route            model.RouteOption
	Proxy            model.ProxyVersion
	RelayEncryptions []model.EncryptionScheme
	DialTimeout      time.Duration
}

// NewDestinationConfig creates a destination config for a given name
func NewDestinationConfig(name string) DestinationConfig {
	return DestinationConfig{
		Endpoint:         model.NewEndpoint(name),
		Route:            model.RouteAny,
		Proxy:            model.ProxyNone,
		RelayEncryptions: []model.EncryptionScheme{model.NoEncryption},
	}
}

// WithRoute sets the route option for this configuration.
func (cfg DestinationConfig) WithRoute(route model.RouteOption) DestinationConfig {
	cfg.Route = route
	return cfg
}

// WithProxy sets the proxy version option for this configuration.
func (cfg DestinationConfig) WithProxy(proxy model.ProxyVersion) DestinationConfig {
	cfg.Proxy = proxy
	return cfg
}

// WithRelayEncryptions sets the relay encryptions option for this configuration.
func (cfg DestinationConfig) WithRelayEncryptions(schemes ...model.EncryptionScheme) DestinationConfig {
	cfg.RelayEncryptions = schemes
	return cfg
}

// WithDialTimeout sets the dial timeout
func (cfg DestinationConfig) WithDialTimeout(timeout time.Duration) DestinationConfig {
	cfg.DialTimeout = timeout
	return cfg
}

type Destination struct {
	cfg    DestinationConfig
	logger *slog.Logger

	peer  *peer
	conns map[peerConnKey]*destinationConn
	ep    *clientEndpoint

	acceptCh chan net.Conn
}

func newDestination(ctx context.Context, cl *Client, cfg DestinationConfig) (*Destination, error) {
	logger := cl.logger.With("destination", cfg.Endpoint)
	p, err := newPeer(cl.directServer, logger)
	if err != nil {
		return nil, err
	}
	if cfg.Route.AllowDirect() {
		p.expectDirect()
	}

	dst := &Destination{
		cfg:    cfg,
		logger: logger,

		peer:  p,
		conns: map[peerConnKey]*destinationConn{},

		acceptCh: make(chan net.Conn),
	}

	ep, err := newClientEndpoint(ctx, cl, dst, logger, func() {
		cl.removeDestination(cfg.Endpoint)
	})
	if err != nil {
		return nil, err
	}
	dst.ep = ep

	return dst, nil
}

func (d *Destination) Config() DestinationConfig {
	return d.cfg
}

func (d *Destination) runPeerErr(ctx context.Context) error {
	defer close(d.acceptCh)

	return reliable.RunGroup(ctx,
		d.peer.run,
		d.runActive,
	)
}

func (d *Destination) runAnnounceErr(ctx context.Context, conn *quic.Conn, directAddrs *notify.V[advertiseAddrs], notifyResponse func(error)) error {
	pc := &peerControl{
		local:    d.peer,
		endpoint: d.cfg.Endpoint,
		role:     model.Destination,
		opt:      d.cfg.Route,
		conn:     conn,
		notify:   notifyResponse,
	}

	if d.cfg.Route.AllowDirect() {
		g, ctx := errgroup.WithContext(ctx)
		g.Go(func() error {
			return directAddrs.Listen(ctx, func(t advertiseAddrs) error {
				d.peer.setDirectAddrs(t.all())
				return nil
			})
		})
		g.Go(func() error { return pc.run(ctx) })
		return g.Wait()
	}

	return pc.run(ctx)
}

func (d *Destination) Accept() (net.Conn, error) {
	return d.AcceptContext(context.Background())
}

func (d *Destination) AcceptContext(ctx context.Context) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn, ok := <-d.acceptCh:
		if !ok {
			return nil, fmt.Errorf("destination %s is closed: %w", d.cfg.Endpoint, net.ErrClosed)
		}
		return conn, nil
	}
}

func (d *Destination) Context() context.Context {
	return d.ep.ctx
}

func (d *Destination) Status() (EndpointStatus, error) {
	return d.ep.status()
}

func (d *Destination) Addr() net.Addr {
	return d.ep.client.directAddr
}

func (d *Destination) Close() error {
	return d.ep.close()
}

func (d *Destination) peerStatus() (PeerStatus, error) {
	return d.peer.status()
}

func (d *Destination) runActive(ctx context.Context) error {
	return d.peer.activeConnsListen(ctx, func(active map[peerConnKey]*quic.Conn) error {
		d.logger.Debug("active conns", "len", len(active))
		for peer, conn := range active {
			if dc := d.conns[peer]; dc != nil {
				if dc.conn == conn {
					continue
				}
				dc.close()
				delete(d.conns, peer)
			}

			dc := newDestinationConn(d, peer, conn, d.logger)
			d.conns[peer] = dc
			go dc.run(ctx)
		}

		for peer, conn := range d.conns {
			if _, ok := active[peer]; !ok {
				conn.close()
				delete(d.conns, peer)
			}
		}
		return nil
	})
}

type destinationConn struct {
	dst    *Destination
	peer   peerConnKey
	conn   *quic.Conn
	logger *slog.Logger

	closer chan struct{}
}

func newDestinationConn(dst *Destination, peer peerConnKey, conn *quic.Conn, logger *slog.Logger) *destinationConn {
	return &destinationConn{
		dst, peer, conn,
		logger.With("peer", peer.id, "style", peer.style),
		make(chan struct{})}
}

func (d *destinationConn) run(ctx context.Context) {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			stream, err := d.conn.AcceptStream(ctx)
			if err != nil {
				d.logger.Debug("accept failed", "err", err)
				return err
			}
			d.logger.Debug("accepted stream new stream")
			go d.runDestination(ctx, stream)
		}
	})
	g.Go(func() error {
		<-d.closer
		return errPeeringStop
	})

	if err := g.Wait(); err != nil {
		d.logger.Debug("error while running destination", "err", err)
	}
}

func (d *destinationConn) runDestination(ctx context.Context, stream *quic.Stream) {
	if err := d.runDestinationErr(ctx, stream); err != nil {
		if err := stream.Close(); err != nil {
			d.logger.Debug("could not close stream on error", "err", err)
		}
		d.logger.Debug("destination conn error", "err", err)
	}
}

func (d *destinationConn) runDestinationErr(ctx context.Context, stream *quic.Stream) error {
	req, err := pbconnect.ReadRequest(stream)
	if err != nil {
		return fmt.Errorf("destination read request: %w", err)
	}

	switch {
	case req.Connect != nil:
		return d.runConnect(ctx, stream, req)
	default:
		return pbconnect.WriteError(stream, pberror.Code_RequestUnknown, "unknown request: %v", req)
	}
}

func (d *destinationConn) runConnect(ctx context.Context, stream *quic.Stream, req *pbconnect.Request) error {
	var srcConfig *tls.Config
	var srcStreamer cryptoc.Streamer

	connect := &pbconnect.Response_Connect{
		ProxyProto: d.dst.cfg.Proxy.PB(),
	}

	if d.peer.style == peerRelay {
		srcEncryptions := model.EncryptionsFromPB(req.Connect.SourceEncryption)
		if len(srcEncryptions) == 0 {
			// source doesn't include encryption logic, none is the only possible choice
			srcEncryptions = []model.EncryptionScheme{model.NoEncryption}
		}

		encryption, err := model.SelectEncryptionScheme(d.dst.cfg.RelayEncryptions, srcEncryptions)
		switch {
		case err != nil:
			return pbconnect.WriteError(stream, pberror.Code_DestinationRelayEncryptionError, "select encryption scheme: %v", err)
		case encryption == model.TLSEncryption:
			scfg, err := d.dst.getSourceTLS(req.Connect.SourceTls.ClientName)
			if err != nil {
				return pbconnect.WriteError(stream, pberror.Code_DestinationRelayEncryptionError, "destination tls: %v", err)
			}
			srcConfig = scfg

			connect.DestinationEncryption = pbconnect.RelayEncryptionScheme_TLS
			connect.DestinationTls = &pbconnect.TLSConfiguration{
				ClientName: d.dst.peer.serverCert.Leaf.DNSNames[0],
			}
		case encryption == model.DHXCPEncryption:
			// get check peer public key
			srcPublic, err := d.dst.peer.getECDHPublicKey(req.Connect.SourceDhX25519)
			if err != nil {
				return pbconnect.WriteError(stream, pberror.Code_DestinationRelayEncryptionError, "destination public key: %v", err)
			}

			dstSecret, ecdhCfg, err := d.dst.peer.newECDHConfig()
			if err != nil {
				return pbconnect.WriteError(stream, pberror.Code_DestinationRelayEncryptionError, "new ecdh config: %v", err)
			}

			connect.DestinationEncryption = pbconnect.RelayEncryptionScheme_DHX25519_CHACHAPOLY
			connect.DestinationDhX25519 = ecdhCfg

			streamer, err := cryptoc.NewStreamer(dstSecret, srcPublic, false)
			if err != nil {
				return pbconnect.WriteError(stream, pberror.Code_DestinationRelayEncryptionError, "new streamer: %v", err)
			}
			srcStreamer = streamer
		case encryption == model.NoEncryption:
			// do nothing
		default:
			return pbconnect.WriteError(stream, pberror.Code_DestinationRelayEncryptionError, "unknown encryption scheme: %s", encryption)
		}
	}

	if err := proto.Write(stream, &pbconnect.Response{
		Connect: connect,
	}); err != nil {
		return fmt.Errorf("destination connect write response: %w", err)
	}

	var encStream = quicc.StreamConn(stream, d.conn)
	if d.peer.style == peerRelay {
		switch connect.DestinationEncryption {
		case pbconnect.RelayEncryptionScheme_TLS:
			d.logger.Debug("upgrading relay connection to TLS")
			tlsConn := tls.Server(quicc.StreamConn(stream, d.conn), srcConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return fmt.Errorf("destination handshake: %w", err)
			}

			encStream = tlsConn
		case pbconnect.RelayEncryptionScheme_DHX25519_CHACHAPOLY:
			d.logger.Debug("upgrading relay connection to DHXCP")
			encStream = srcStreamer(encStream)
		case pbconnect.RelayEncryptionScheme_EncryptionNone:
			// do nothing
		default:
		}
	}

	d.logger.Debug("accepted conn", "style", d.peer.style)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.closer:
		return errPeeringStop
	case d.dst.acceptCh <- encStream:
		return nil
	}
}

func (d *destinationConn) close() {
	close(d.closer)
}

func (d *Destination) getSourceTLS(name string) (*tls.Config, error) {
	remotes, err := d.peer.peers.Peek()
	if err != nil {
		return nil, fmt.Errorf("source peers list: %w", err)
	}

	for _, remote := range remotes {
		switch cfg, err := newServerTLSConfig(remote.Peer.ServerCertificate); {
		case err != nil:
			return nil, fmt.Errorf("source peer server cert: %w", err)
		case cfg.name == name:
			clientCert, err := x509.ParseCertificate(remote.Peer.ClientCertificate)
			if err != nil {
				return nil, fmt.Errorf("source peer client cert: %w", err)
			}

			clientCAs := x509.NewCertPool()
			clientCAs.AddCert(clientCert)
			return &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{d.peer.serverCert},
				ClientCAs:    clientCAs,
			}, nil
		}
	}

	return nil, fmt.Errorf("source peer %s not found", name)
}

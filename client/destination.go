package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/cryptoc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type DestinationConfig struct {
	Forward          model.Forward
	Address          string
	Route            model.RouteOption
	Proxy            model.ProxyVersion
	RelayEncryptions []model.EncryptionScheme
}

func NewDestinationConfig(name string, addr string) DestinationConfig {
	return DestinationConfig{
		Forward:          model.NewForward(name),
		Address:          addr,
		Route:            model.RouteAny,
		Proxy:            model.ProxyNone,
		RelayEncryptions: []model.EncryptionScheme{model.NoEncryption},
	}
}

func (cfg DestinationConfig) WithRoute(route model.RouteOption) DestinationConfig {
	cfg.Route = route
	return cfg
}

func (cfg DestinationConfig) WithProxy(proxy model.ProxyVersion) DestinationConfig {
	cfg.Proxy = proxy
	return cfg
}

func (cfg DestinationConfig) WithRelayEncryptions(schemes ...model.EncryptionScheme) DestinationConfig {
	cfg.RelayEncryptions = schemes
	return cfg
}

type Destination struct {
	cfg    DestinationConfig
	logger *slog.Logger

	peer  *peer
	conns map[peerConnKey]*destinationConn
}

func NewDestination(cfg DestinationConfig, direct *DirectServer, root *certc.Cert, logger *slog.Logger) (*Destination, error) {
	logger = logger.With("destination", cfg.Forward)
	p, err := newPeer(direct, root, logger)
	if err != nil {
		return nil, err
	}
	if cfg.Route.AllowDirect() {
		p.expectDirect()
	}

	return &Destination{
		cfg:    cfg,
		logger: logger,

		peer:  p,
		conns: map[peerConnKey]*destinationConn{},
	}, nil
}

func (d *Destination) SetDirectAddrs(addrs []netip.AddrPort) {
	if !d.cfg.Route.AllowDirect() {
		return
	}

	d.peer.setDirectAddrs(addrs)
}

func (d *Destination) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return d.peer.run(ctx) })
	g.Go(func() error { return d.runActive(ctx) })

	return g.Wait()
}

func (d *Destination) Status() (PeerStatus, error) {
	return d.peer.status()
}

func (d *Destination) runActive(ctx context.Context) error {
	return d.peer.activeConnsListen(ctx, func(active map[peerConnKey]quic.Connection) error {
		d.logger.Debug("active conns", "len", len(active))
		for peer, conn := range active {
			if dc := d.conns[peer]; dc != nil {
				if dc.conn == conn {
					continue
				}
				dc.close()
				delete(d.conns, peer)
			}

			dc := newDestinationConn(d, peer, conn)
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
	dst  *Destination
	peer peerConnKey
	conn quic.Connection

	closer chan struct{}
}

func newDestinationConn(dst *Destination, peer peerConnKey, conn quic.Connection) *destinationConn {
	return &destinationConn{dst, peer, conn, make(chan struct{})}
}

func (d *destinationConn) run(ctx context.Context) {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			stream, err := d.conn.AcceptStream(ctx)
			if err != nil {
				d.dst.logger.Debug("accept failed", "peer", d.peer.id, "style", d.peer.style, "err", err)
				return err
			}
			d.dst.logger.Debug("accepted stream from", "peer", d.peer.id, "style", d.peer.style)
			go d.dst.runDestination(ctx, stream, d)
		}
	})
	g.Go(func() error {
		<-d.closer
		return errPeeringStop
	})

	if err := g.Wait(); err != nil {
		d.dst.logger.Debug("error while running destination", "err", err)
	}
}

func (d *destinationConn) close() {
	close(d.closer)
}

func (d *Destination) runDestination(ctx context.Context, stream quic.Stream, src *destinationConn) {
	defer stream.Close()

	if err := d.runDestinationErr(ctx, stream, src); err != nil {
		d.logger.Debug("destination conn error", "err", err)
	}
}

func (d *Destination) runDestinationErr(ctx context.Context, stream quic.Stream, src *destinationConn) error {
	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return fmt.Errorf("destination read request: %w", err)
	}

	switch {
	case req.Connect != nil:
		return d.runConnect(ctx, stream, src, req)
	default:
		err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return fmt.Errorf("destination write err response: %w", err)
		}
		return err
	}
}

func (d *Destination) runConnect(ctx context.Context, stream quic.Stream, src *destinationConn, req *pbc.Request) error {
	// TODO check allow from?

	var srcConfig *tls.Config
	var srcStreamer cryptoc.Streamer

	connect := &pbc.Response_Connect{
		ProxyProto: d.cfg.Proxy.PB(),
	}

	if src.peer.style == peerRelay {
		srcEncryptions := model.EncryptionsFromPB(req.Connect.SourceEncryption)
		if len(srcEncryptions) == 0 {
			// source doesn't include encryption logic, none is the only possible choice
			srcEncryptions = []model.EncryptionScheme{model.NoEncryption}
		}

		encryption, err := model.SelectEncryptionScheme(d.cfg.RelayEncryptions, srcEncryptions)
		switch {
		case err != nil:
			return pbc.WriteError(stream, pb.Error_DestinationRelayEncryptionError, "select encryption scheme: %v", err)
		case encryption == model.TLSEncryption:
			scfg, err := d.getSourceTLS(req.Connect.SourceTls.ClientName)
			if err != nil {
				return pbc.WriteError(stream, pb.Error_DestinationRelayEncryptionError, "destination tls: %v", err)
			}
			srcConfig = scfg

			connect.DestinationEncryption = pbc.RelayEncryptionScheme_TLS
			connect.DestinationTls = &pbc.TLSConfiguration{
				ClientName: d.peer.serverCert.Leaf.DNSNames[0],
			}
		case encryption == model.DHXCPEncryption:
			// get check peer public key
			srcPublic, err := d.peer.getECDHPublicKey(req.Connect.SourceDhX25519)
			if err != nil {
				return pbc.WriteError(stream, pb.Error_DestinationRelayEncryptionError, "destination public key: %v", err)
			}

			dstSecret, ecdhCfg, err := d.peer.newECDHConfig()
			if err != nil {
				return pbc.WriteError(stream, pb.Error_DestinationRelayEncryptionError, "new ecdh config: %v", err)
			}

			connect.DestinationEncryption = pbc.RelayEncryptionScheme_DHX25519_CHACHAPOLY
			connect.DestinationDhX25519 = ecdhCfg

			streamer, err := cryptoc.NewStreamer(dstSecret, srcPublic, false)
			if err != nil {
				return pbc.WriteError(stream, pb.Error_DestinationRelayEncryptionError, "new streamer: %v", err)
			}
			srcStreamer = streamer
		case encryption == model.NoEncryption:
			// do nothing
		default:
			return pbc.WriteError(stream, pb.Error_DestinationRelayEncryptionError, "unknown encryption scheme: %s", encryption)
		}
	}

	conn, err := net.Dial("tcp", d.cfg.Address)
	if err != nil {
		return pbc.WriteError(stream, pb.Error_DestinationDialFailed, "%s could not be dialed: %v", d.cfg.Forward, err)
	}
	defer conn.Close()

	if err := pb.Write(stream, &pbc.Response{
		Connect: connect,
	}); err != nil {
		return fmt.Errorf("destination connect write response: %w", err)
	}

	var encStream io.ReadWriteCloser = stream
	if src.peer.style == peerRelay {
		switch connect.DestinationEncryption {
		case pbc.RelayEncryptionScheme_TLS:
			d.logger.Debug("upgrading relay connection to TLS", "peer", src.peer.id)
			tlsConn := tls.Server(quicc.StreamConn(stream, src.conn), srcConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return fmt.Errorf("destination handshake: %w", err)
			}

			encStream = tlsConn
		case pbc.RelayEncryptionScheme_DHX25519_CHACHAPOLY:
			d.logger.Debug("upgrading relay connection to DHXCP", "peer", src.peer.id)
			encStream = srcStreamer(stream)
		case pbc.RelayEncryptionScheme_EncryptionNone:
			// do nothing
		default:
		}
	}

	d.logger.Debug("joining conns")
	err = netc.Join(ctx, encStream, conn)
	d.logger.Debug("disconnected conns", "err", err)

	return nil
}

func (d *Destination) RunControl(ctx context.Context, conn quic.Connection) error {
	return (&peerControl{
		local: d.peer,
		fwd:   d.cfg.Forward,
		role:  model.Destination,
		opt:   d.cfg.Route,
		conn:  conn,
	}).run(ctx)
}

func (d *Destination) getSourceTLS(name string) (*tls.Config, error) {
	peers, err := d.peer.peers.Peek()
	if err != nil {
		return nil, fmt.Errorf("source peers list: %w", err)
	}

	for _, peer := range peers {
		switch cfg, err := newServerTLSConfig(peer.ServerCertificate); {
		case err != nil:
			return nil, fmt.Errorf("source peer server cert: %w", err)
		case cfg.name == name:
			clientCert, err := x509.ParseCertificate(peer.ClientCertificate)
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

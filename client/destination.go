package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	es "github.com/nknorg/encrypted-stream"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sync/errgroup"
)

type DestinationConfig struct {
	Forward model.Forward
	Address string
	Route   model.RouteOption
	Proxy   model.ProxyVersion
}

func NewDestinationConfig(name string, addr string) DestinationConfig {
	return DestinationConfig{Forward: model.NewForward(name), Address: addr, Route: model.RouteAny, Proxy: model.ProxyNone}
}

func (cfg DestinationConfig) WithRoute(route model.RouteOption) DestinationConfig {
	cfg.Route = route
	return cfg
}

func (cfg DestinationConfig) WithProxy(proxy model.ProxyVersion) DestinationConfig {
	cfg.Proxy = proxy
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
			go d.dst.runDestination(ctx, stream, d.peer)
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

func (d *Destination) runDestination(ctx context.Context, stream quic.Stream, src peerConnKey) {
	defer stream.Close()

	if err := d.runDestinationErr(ctx, stream, src); err != nil {
		d.logger.Debug("done destination")
	}
}

func (d *Destination) runDestinationErr(ctx context.Context, stream quic.Stream, src peerConnKey) error {
	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
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

func (d *Destination) runConnect(ctx context.Context, stream quic.Stream, src peerConnKey, req *pbc.Request) error {
	// TODO check allow from?

	if src.style == peerRelay {
		cert, err := d.peer.findPeerByName(req.Connect.SourceClientName)
		if err != nil {
			return fmt.Errorf("find peer: %w", err)
		}
		peerPublicKey := cert.PublicKey.(ed25519.PublicKey)
		if !ed25519.Verify(peerPublicKey, req.Connect.SourceClientKey, req.Connect.SourceClientSign) {
			return fmt.Errorf("signature not verified")
		}
	}

	conn, err := net.Dial("tcp", d.cfg.Address)
	if err != nil {
		err := pb.NewError(pb.Error_DestinationDialFailed, "%s could not be dialed: %v", d.cfg.Forward, err)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return fmt.Errorf("connect write err response: %w", err)
		}
		return err
	}
	defer conn.Close()

	var dstName string
	var sendKey, signKey []byte
	var pk, sk *[32]byte
	if src.style == peerRelay {
		dstName = d.peer.serverCert.Leaf.DNSNames[0]

		pk, sk, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		sendKey = (*pk)[:]

		pk := d.peer.serverCert.PrivateKey.(ed25519.PrivateKey)
		sign, err := pk.Sign(nil, sendKey, &ed25519.Options{})
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		signKey = sign
	}

	if err := pb.Write(stream, &pbc.Response{
		Connect: &pbc.Response_Connect{
			ProxyProto:            d.cfg.Proxy.PB(),
			DestinationClientName: dstName,
			DestinationClientKey:  sendKey,
			DestinationClientSign: signKey,
		},
	}); err != nil {
		return fmt.Errorf("connect write response: %w", err)
	}

	var srcStream io.ReadWriteCloser = stream
	if src.style == peerRelay {
		var sharedKey, peerPubKey [32]byte
		copy(peerPubKey[:], req.Connect.SourceClientKey)
		box.Precompute(&sharedKey, &peerPubKey, sk)

		c, err := es.NewXChaCha20Poly1305Cipher(sharedKey[:])
		if err != nil {
			return fmt.Errorf("create chachapoly cipher: %w", err)
		}
		s, err := es.NewEncryptedStream(stream, &es.Config{
			Cipher:    c,
			Initiator: false,
		})
		if err != nil {
			return fmt.Errorf("create encrypted stream: %w", err)
		}
		srcStream = s
	}

	d.logger.Debug("joining conns")
	err = netc.Join(ctx, srcStream, conn)
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

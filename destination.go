package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/cryptoc"
	"github.com/connet-dev/connet/pkg/quicc"
	"github.com/connet-dev/connet/pkg/statusc"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/quic-go/quic-go"
)

var ErrDestinationClosed = fmt.Errorf("destination closed: %w", errEndpointClosed)
var errDestinationConnUpdated = errors.New("destination connection updated")
var errDestinationConnRemoved = errors.New("destination connection removed")

// Destination represents an endpoint that accepts connections from remote endpoints
// It implements [net.Listener] on top of connet infrastructure
type Destination struct {
	cfg DestinationConfig
	ep  *endpoint

	acceptCh chan net.Conn

	logger *slog.Logger
}

func newDestination(ctx context.Context, cl *Client, cfg DestinationConfig) (*Destination, error) {
	logger := cl.logger.With("destination", cfg.Endpoint)

	ep, err := newEndpoint(ctx, cl, cfg.endpointConfig(), logger)
	if err != nil {
		return nil, err
	}

	dst := &Destination{
		cfg: cfg,
		ep:  ep,

		acceptCh: make(chan net.Conn),

		logger: logger,
	}

	go dst.runActive(ep.ctx)

	return dst, nil
}

// Accept calls [Destination.AcceptContext] with [context.Background]
func (d *Destination) Accept() (net.Conn, error) {
	return d.AcceptContext(context.Background())
}

// AcceptContext waits for a new connection from remote sources. It blocks until
// a new connection comes it or the destination is closed
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

// Config returns the original [DestinationConfig] used to start this destination
func (d *Destination) Config() DestinationConfig {
	return d.cfg
}

// Context returns [context.Context] associated with the lifetime of this destination.
// Once the destination is closed, this context will be canceled
func (d *Destination) Context() context.Context {
	return d.ep.ctx
}

// DestinationStatus describes the status of a destination
type DestinationStatus struct {
	// Overall status of this destination
	Status statusc.Status `json:"status"`
	// Peer status for this destination
	StatusPeer
}

// Status returns the current status of this destination
func (d *Destination) Status() (DestinationStatus, error) {
	stat, err := d.ep.status()
	return DestinationStatus(stat), err
}

// Addr returns the local address that client listens on
func (d *Destination) Addr() net.Addr {
	return d.ep.client.directAddr
}

// Close closes this destination. Any active connections are also closed.
// Any blocked accept operations will be unblocked and return errors.
func (d *Destination) Close() error {
	return d.ep.close(ErrDestinationClosed)
}

func (d *Destination) runActive(ctx context.Context) {
	defer close(d.acceptCh)

	if err := d.runActiveErr(ctx); err != nil {
		d.logger.Debug("run active exited", "err", err) // TODO
	}
}

func (d *Destination) runActiveErr(ctx context.Context) error {
	var conns = map[peerConnKey]*destinationConn{}
	defer func() {
		for peer, conn := range conns {
			conn.cancel(ErrDestinationClosed)
			delete(conns, peer)
		}
	}()

	return d.ep.peer.activeConnsListen(ctx, func(active map[peerConnKey]*quic.Conn) error {
		d.logger.Debug("active conns", "len", len(active))
		for peer, conn := range active {
			if dc := conns[peer]; dc != nil {
				if dc.conn == conn {
					continue
				}
				dc.cancel(errDestinationConnUpdated)
				delete(conns, peer)
			}

			conns[peer] = runDestinationConn(ctx, d, peer, conn, d.logger)
		}

		for peer, conn := range conns {
			if _, ok := active[peer]; !ok {
				conn.cancel(errDestinationConnRemoved)
				delete(conns, peer)
			}
		}
		return nil
	})
}

func (d *Destination) getSourceTLS(name string) (*tls.Config, error) {
	remotes, ok := d.ep.peer.peers.Peek()
	if !ok {
		return nil, fmt.Errorf("source peer %s not found: no remotes", name)
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
				Certificates: []tls.Certificate{d.ep.peer.serverCert},
				ClientCAs:    clientCAs,
			}, nil
		}
	}

	return nil, fmt.Errorf("source peer %s not found", name)
}

type destinationConn struct {
	dst    *Destination
	peer   peerConnKey
	conn   *quic.Conn
	logger *slog.Logger
	cancel context.CancelCauseFunc
}

func runDestinationConn(ctx context.Context, dst *Destination, peer peerConnKey, conn *quic.Conn, logger *slog.Logger) *destinationConn {
	ctx, cancel := context.WithCancelCause(ctx)
	c := &destinationConn{dst, peer, conn, logger.With("peer", peer.id, "style", peer.style), cancel}
	go c.run(ctx)
	return c
}

func (d *destinationConn) run(ctx context.Context) {
	if err := d.runErr(ctx); err != nil {
		d.logger.Debug("error while running destination", "err", err)
	}
}

func (d *destinationConn) runErr(ctx context.Context) error {
	for {
		stream, err := d.conn.AcceptStream(ctx)
		if err != nil {
			d.logger.Debug("accept failed", "err", err)
			return err
		}
		d.logger.Debug("accepted stream new stream")
		go d.runDestination(ctx, stream)
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

	if d.peer.style.isRelay() {
		srcEncryptions, err := model.EncryptionsFromPB(req.Connect.SourceEncryption)
		switch {
		case err != nil:
			return pbconnect.WriteError(stream, pberror.Code_DestinationRelayEncryptionError, "failed to negotiate encryption: %v", err)
		case len(srcEncryptions) == 0:
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
				ClientName: d.dst.ep.peer.serverCert.Leaf.DNSNames[0],
			}
		case encryption == model.DHXCPEncryption:
			// get check peer public key
			srcPublic, err := d.dst.ep.peer.getECDHPublicKey(req.Connect.SourceDhX25519)
			if err != nil {
				return pbconnect.WriteError(stream, pberror.Code_DestinationRelayEncryptionError, "destination public key: %v", err)
			}

			dstSecret, ecdhCfg, err := d.dst.ep.peer.newECDHConfig()
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
	if d.peer.style.isRelay() {
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
		return context.Cause(ctx)
	case <-stream.Context().Done():
		return context.Cause(stream.Context())
	case <-d.conn.Context().Done():
		return context.Cause(d.conn.Context())
	case d.dst.acceptCh <- encStream:
		return nil
	}
}

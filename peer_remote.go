package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pbconnect"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/quicc"
	"github.com/connet-dev/connet/reliable"
	"github.com/connet-dev/connet/slogc"
	"github.com/quic-go/quic-go"
)

var errRemotePeerRemoved = errors.New("remote peer removed")
var errRemotePeerPathRemoved = errors.New("remote peer path removed")

func isPeerTerminalError(err error) bool {
	switch {
	case errors.Is(err, context.Canceled):
		return true
	case errors.Is(err, errRemotePeerRemoved):
		return true
	case errors.Is(err, errRemotePeerPathRemoved):
		return true
	}
	return false
}

type remotePeer struct {
	local *peer

	remoteID peerID
	remote   *notify.V[*pbclient.RemotePeer]
	incoming *remotePeerIncoming
	outgoing *remotePeerOutgoing
	relays   *remotePeerRelays

	cancel context.CancelCauseFunc
	logger *slog.Logger
}

func runRemotePeer(ctx context.Context, local *peer, remote *pbclient.RemotePeer, logger *slog.Logger) *remotePeer {
	ctx, cancel := context.WithCancelCause(ctx)
	r := &remotePeer{
		local: local,

		remoteID: peerID(remote.Id),
		remote:   notify.New(remote),

		cancel: cancel,
		logger: logger.With("peer", remote.Id),
	}
	go r.run(ctx)
	return r
}

func (p *remotePeer) run(ctx context.Context) {
	defer p.cancel(nil) // just a context cancel

	defer func() {
		p.local.removeActiveConns(p.remoteID)
	}()

	if err := p.runErr(ctx); err != nil {
		p.logger.Debug("error running remote peer", "err", err)
		// p.cancel()
	}
}

func (p *remotePeer) runErr(ctx context.Context) error {
	return p.remote.Listen(ctx, func(remote *pbclient.RemotePeer) error {
		if p.local.allowDirect && len(remote.Peer.Directs) > 0 {
			if p.incoming == nil {
				remoteClientCert, err := x509.ParseCertificate(remote.Peer.ClientCertificate)
				if err != nil {
					return fmt.Errorf("parse client certificate: %w", err)
				}
				p.incoming = runRemotePeerIncoming(ctx, p, remoteClientCert)
			}

			if p.outgoing == nil {
				remoteServerConf, err := newServerTLSConfig(remote.Peer.ServerCertificate)
				if err != nil {
					return fmt.Errorf("parse server certificate: %w", err)
				}

				addrs := map[netip.AddrPort]struct{}{}
				for _, addr := range remote.Peer.Directs {
					addrs[addr.AsNetip()] = struct{}{}
				}
				p.outgoing = runRemotePeerOutgoing(ctx, p, remoteServerConf, addrs)
			}
		} else {
			if p.incoming != nil {
				p.incoming.cancel(errRemotePeerPathRemoved)
				p.incoming = nil
			}
			if p.outgoing != nil {
				p.outgoing.cancel(errRemotePeerPathRemoved)
				p.outgoing = nil
			}
		}

		remotes := map[relayID]struct{}{}
		for _, id := range remote.Peer.RelayIds {
			remotes[relayID(id)] = struct{}{}
		}

		switch {
		case len(remotes) > 0 && p.relays == nil:
			p.relays = runRemotePeerRelays(ctx, p, remotes)
		case len(remotes) > 0 && p.relays != nil:
			p.relays.remotes.Set(remotes)
		case len(remotes) == 0 && p.relays != nil:
			p.relays.cancel(errRemotePeerPathRemoved)
			p.relays = nil
		case len(remotes) == 0 && p.relays == nil:
			// do nothing, since remote is not running
		}

		return nil
	})
}

type remotePeerIncoming struct {
	parent     *remotePeer
	clientCert *x509.Certificate
	cancel     context.CancelCauseFunc
	logger     *slog.Logger
}

func runRemotePeerIncoming(ctx context.Context, parent *remotePeer, clientCert *x509.Certificate) *remotePeerIncoming {
	ctx, cancel := context.WithCancelCause(ctx)
	p := &remotePeerIncoming{
		parent:     parent,
		clientCert: clientCert,
		cancel:     cancel,
		logger:     parent.logger.With("style", "incoming"),
	}
	go p.run(ctx)
	return p
}

func (p *remotePeerIncoming) run(ctx context.Context) {
	boff := reliable.MinBackoff
	for {
		conn, err := p.connect(ctx)
		if err != nil {
			p.logger.Debug("could not connect", "err", err)
			if isPeerTerminalError(err) {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(boff):
				boff = reliable.NextBackoff(boff)
			}
			continue
		}
		boff = reliable.MinBackoff

		if err := p.keepalive(ctx, conn); err != nil {
			p.logger.Debug("keepalive failed", "err", err)
			if isPeerTerminalError(err) {
				return
			}
		}
	}
}

func (p *remotePeerIncoming) connect(ctx context.Context) (*quic.Conn, error) {
	ch, cancel := p.parent.local.direct.expect(p.parent.local.serverCert, p.clientCert)
	select {
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	case conn := <-ch: // TODO panic on closing channel?
		if err := p.check(ctx, conn); err != nil {
			cerr := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_ConnectionCheckFailed), "connection check failed")
			return nil, fmt.Errorf("connection check failed: %w", errors.Join(err, cerr))
		}

		return conn, nil
	}
}

func (p *remotePeerIncoming) check(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(p.logger, "error closing check stream", "err", err)
		}
	}()

	if _, err := pbconnect.ReadRequest(stream); err != nil {
		return err
	} else if err := proto.Write(stream, &pbconnect.Response{}); err != nil {
		return err
	}

	return nil
}

func (p *remotePeerIncoming) keepalive(ctx context.Context, conn *quic.Conn) error {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_DirectKeepaliveClosed), "keepalive closed"); err != nil {
			slogc.Fine(p.logger, "error closing connection", "err", err)
		}
	}()

	p.parent.local.addActiveConn(p.parent.remoteID, peerIncoming, "", conn)
	defer p.parent.local.removeActiveConn(p.parent.remoteID, peerIncoming, "")

	return quicc.WaitLogRTTStats(ctx, conn, p.logger)
}

type remotePeerOutgoing struct {
	parent     *remotePeer
	serverConf *serverTLSConfig
	addrs      map[netip.AddrPort]struct{}
	cancel     context.CancelCauseFunc
	logger     *slog.Logger
}

func runRemotePeerOutgoing(ctx context.Context, parent *remotePeer, serverConfg *serverTLSConfig, addrs map[netip.AddrPort]struct{}) *remotePeerOutgoing {
	ctx, cancel := context.WithCancelCause(ctx)
	p := &remotePeerOutgoing{
		parent:     parent,
		serverConf: serverConfg,
		addrs:      addrs,
		cancel:     cancel,
		logger:     parent.logger.With("style", "outgoing"),
	}
	go p.run(ctx)
	return p
}

func (p *remotePeerOutgoing) run(ctx context.Context) {
	boff := reliable.MinBackoff
	for {
		conn, err := p.connect(ctx)
		if err != nil {
			p.logger.Debug("could not connect", "err", err)
			if isPeerTerminalError(err) {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(boff):
				boff = reliable.NextBackoff(boff)
			}
			continue
		}
		boff = reliable.MinBackoff

		if err := p.keepalive(ctx, conn); err != nil {
			p.logger.Debug("keepalive failed", "err", err)
			if isPeerTerminalError(err) {
				return
			}
		}
	}
}

func (p *remotePeerOutgoing) connect(ctx context.Context) (*quic.Conn, error) {
	var errs []error
	for paddr := range p.addrs {
		addr := net.UDPAddrFromAddrPort(paddr)

		p.logger.Debug("dialing direct", "addr", addr, "server", p.serverConf.name, "cert", p.serverConf.key)
		conn, err := p.parent.local.direct.transport.Dial(ctx, addr, &tls.Config{
			Certificates: []tls.Certificate{p.parent.local.clientCert},
			RootCAs:      p.serverConf.cas,
			ServerName:   p.serverConf.name,
			NextProtos:   model.ConnectDirectNextProtos,
		}, quicc.StdConfig)
		switch {
		case isPeerTerminalError(err):
			return nil, err
		case err != nil:
			errs = append(errs, err)
			continue
		}

		switch err := p.check(ctx, conn); {
		case errors.Is(err, context.Canceled):
			return nil, err
		case err != nil:
			errs = append(errs, err)
			cerr := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_ConnectionCheckFailed), "connection check failed")
			errs = append(errs, cerr)
			continue
		}

		return conn, nil
	}
	return nil, errors.Join(errs...)
}

func (p *remotePeerOutgoing) check(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := stream.Close(); err != nil {
			slogc.Fine(p.logger, "error closing check stream", "err", err)
		}
	}()

	if err := proto.Write(stream, &pbconnect.Request{}); err != nil {
		return err
	}
	if _, err := pbconnect.ReadResponse(stream); err != nil {
		return err
	}

	return nil
}

func (p *remotePeerOutgoing) keepalive(ctx context.Context, conn *quic.Conn) error {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_DirectKeepaliveClosed), "keepalive closed"); err != nil {
			slogc.Fine(p.logger, "error closing connection", "err", err)
		}
	}()

	p.parent.local.addActiveConn(p.parent.remoteID, peerOutgoing, "", conn)
	defer p.parent.local.removeActiveConn(p.parent.remoteID, peerOutgoing, "")

	return quicc.WaitLogRTTStats(ctx, conn, p.logger)
}

type remotePeerRelays struct {
	parent  *remotePeer
	remotes *notify.V[map[relayID]struct{}]
	cancel  context.CancelCauseFunc
	logger  *slog.Logger
}

func runRemotePeerRelays(ctx context.Context, parent *remotePeer, remotes map[relayID]struct{}) *remotePeerRelays {
	ctx, cancel := context.WithCancelCause(ctx)
	p := &remotePeerRelays{
		parent:  parent,
		remotes: notify.New(remotes),
		cancel:  cancel,
		logger:  parent.logger.With("style", "relay"),
	}
	go p.run(ctx)
	return p
}

func (p *remotePeerRelays) run(ctx context.Context) {
	active := map[relayID]struct{}{}
	defer func() {
		for id := range active {
			p.parent.local.removeActiveConn(p.parent.remoteID, peerRelay, string(id))
		}
	}()

	update := func(ctx context.Context, locals map[relayID]*quic.Conn, remotes map[relayID]struct{}) error {
		for id := range active {
			_, relayed := locals[id]
			_, remoteByID := remotes[id]
			if !relayed || !remoteByID {
				p.parent.local.removeActiveConn(p.parent.remoteID, peerRelay, string(id))
				delete(active, id)
			}
		}

		for id := range remotes {
			if conn, ok := locals[id]; ok {
				if _, ok := active[id]; !ok {
					active[id] = struct{}{}
					p.parent.local.addActiveConn(p.parent.remoteID, peerRelay, string(id), conn)
				}
			}
		}

		return nil
	}

	if err := notify.ListenMulti(ctx, p.parent.local.relayConns, p.remotes, update); err != nil {
		p.logger.Debug("error running peer relays", "err", err)
	}
}

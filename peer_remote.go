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
	"golang.org/x/sync/errgroup"
)

type remotePeer struct {
	local *peer

	remoteID peerID
	remote   *notify.V[*pbclient.RemotePeer]
	incoming *remotePeerIncoming
	outgoing *remotePeerOutgoing
	relays   *remotePeerRelays

	closer chan struct{}

	logger *slog.Logger
}

func newRemotePeer(local *peer, remote *pbclient.RemotePeer, logger *slog.Logger) *remotePeer {
	return &remotePeer{
		local: local,

		remoteID: peerID(remote.Id),
		remote:   notify.New(remote),

		closer: make(chan struct{}),

		logger: logger.With("peer", remote.Id),
	}
}

var errPeeringStop = errors.New("peering stopped")

func (p *remotePeer) run(ctx context.Context) {
	defer func() {
		p.local.removeActiveConns(p.remoteID)
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return p.runRemote(ctx) })
	g.Go(func() error {
		<-p.closer
		return errPeeringStop
	})

	if err := g.Wait(); err != nil {
		p.logger.Debug("error while running peering", "err", err)
	}
}

func (p *remotePeer) stop() {
	close(p.closer)
}

func (p *remotePeer) runRemote(ctx context.Context) error {
	defer func() {
		if p.incoming != nil {
			close(p.incoming.closer)
		}
		if p.outgoing != nil {
			close(p.outgoing.closer)
		}
		if p.relays != nil {
			close(p.relays.closerCh)
		}
	}()
	return p.remote.Listen(ctx, func(remote *pbclient.RemotePeer) error {
		if p.local.isDirect() && len(remote.Peer.Directs) > 0 {
			if p.incoming == nil {
				remoteClientCert, err := x509.ParseCertificate(remote.Peer.ClientCertificate)
				if err != nil {
					return fmt.Errorf("parse client certificate: %w", err)
				}
				p.incoming = newRemotePeerIncoming(ctx, p, remoteClientCert)
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
				p.outgoing = newRemotePeerOutgoing(ctx, p, remoteServerConf, addrs)
			}
		} else {
			if p.incoming != nil {
				close(p.incoming.closer)
				p.incoming = nil
			}
			if p.outgoing != nil {
				close(p.outgoing.closer)
				p.outgoing = nil
			}
		}

		remotes := map[relayID]struct{}{}
		for _, id := range remote.Peer.RelayIds {
			remotes[relayID(id)] = struct{}{}
		}

		switch {
		case p.relays == nil:
			p.relays = newRemotePeerRelays(ctx, p, remotes)
		case len(remotes) == 0:
			close(p.relays.closerCh)
			p.relays = nil
		default:
			p.relays.remotes.Set(remotes)
		}

		return nil
	})
}

var errClosed = errors.New("closed")

func isPeerTerminalError(err error) bool {
	switch {
	case errors.Is(err, context.Canceled):
		return true
	case errors.Is(err, errClosed):
		return true
	case errors.Is(err, errPeeringStop):
		return true
	}
	return false
}

type remotePeerIncoming struct {
	parent     *remotePeer
	clientCert *x509.Certificate
	closer     chan struct{}
	logger     *slog.Logger
}

func newRemotePeerIncoming(ctx context.Context, parent *remotePeer, clientCert *x509.Certificate) *remotePeerIncoming {
	p := &remotePeerIncoming{
		parent:     parent,
		clientCert: clientCert,
		closer:     make(chan struct{}),
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
			case <-p.closer:
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
	case <-p.closer:
		cancel()
		return nil, errClosed
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	case conn := <-ch: // TODO panic on closing channel?
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := stream.Close(); err != nil {
				slogc.Fine(p.logger, "error closing check stream", "err", err)
			}
		}()

		if _, err := pbconnect.ReadRequest(stream); err != nil {
			return nil, err
		} else if err := proto.Write(stream, &pbconnect.Response{}); err != nil {
			return nil, err
		}

		return conn, nil
	}
}

func (p *remotePeerIncoming) keepalive(ctx context.Context, conn *quic.Conn) error {
	defer func() {
		if err := conn.CloseWithError(quic.ApplicationErrorCode(pberror.Code_DirectKeepaliveClosed), "keepalive closed"); err != nil {
			slogc.Fine(p.logger, "error closing connection", "err", err)
		}
	}()

	p.parent.local.addActiveConn(p.parent.remoteID, peerIncoming, "", conn)
	defer p.parent.local.removeActiveConn(p.parent.remoteID, peerIncoming, "")

	quicc.LogRTTStats(conn, p.logger)
	for {
		select {
		case <-p.closer:
			return errClosed
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-conn.Context().Done():
			return context.Cause(conn.Context())
		case <-time.After(30 * time.Second):
			quicc.LogRTTStats(conn, p.logger)
		}
	}
}

type remotePeerOutgoing struct {
	parent     *remotePeer
	serverConf *serverTLSConfig
	addrs      map[netip.AddrPort]struct{}
	closer     chan struct{}
	logger     *slog.Logger
}

func newRemotePeerOutgoing(ctx context.Context, parent *remotePeer, serverConfg *serverTLSConfig, addrs map[netip.AddrPort]struct{}) *remotePeerOutgoing {
	p := &remotePeerOutgoing{
		parent:     parent,
		serverConf: serverConfg,
		addrs:      addrs,
		closer:     make(chan struct{}),
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
			case <-p.closer:
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

	quicc.LogRTTStats(conn, p.logger)
	for {
		select {
		case <-p.closer:
			return errClosed
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-conn.Context().Done():
			return context.Cause(conn.Context())
		case <-time.After(30 * time.Second):
			quicc.LogRTTStats(conn, p.logger)
		}
	}
}

type remotePeerRelays struct {
	parent   *remotePeer
	remotes  *notify.V[map[relayID]struct{}]
	closerCh chan struct{}
}

func newRemotePeerRelays(ctx context.Context, parent *remotePeer, remotes map[relayID]struct{}) *remotePeerRelays {
	p := &remotePeerRelays{
		parent:   parent,
		remotes:  notify.New(remotes),
		closerCh: make(chan struct{}),
	}
	go p.run(ctx)
	return p
}

func (p *remotePeerRelays) run(ctx context.Context) {
	var (
		locals  map[relayID]*quic.Conn
		remotes map[relayID]struct{}
	)

	active := map[relayID]model.HostPort{}
	defer func() {
		for id := range active {
			p.parent.local.removeActiveConn(p.parent.remoteID, peerRelay, string(id))
		}
	}()

	update := func() {
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
					p.parent.local.addActiveConn(p.parent.remoteID, peerRelay, string(id), conn)
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	relaysCh := p.parent.local.relayConns.Notify(ctx)
	remoteCh := p.remotes.Notify(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.closerCh:
			return
		case locals = <-relaysCh:
			update()
		case remotes = <-remoteCh:
			update()
		}
	}
}

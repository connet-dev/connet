package client

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
	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/pbc"
	"github.com/connet-dev/connet/pbs"
	"github.com/connet-dev/connet/quicc"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type directPeer struct {
	local *peer

	remoteID string
	remote   *notify.V[*pbs.ServerPeer]
	incoming *directPeerIncoming
	outgoing *directPeerOutgoing
	relays   *directPeerRelays

	closer chan struct{}

	logger *slog.Logger
}

func newPeering(local *peer, remote *pbs.ServerPeer, logger *slog.Logger) *directPeer {
	return &directPeer{
		local: local,

		remoteID: remote.Id,
		remote:   notify.New(remote),

		closer: make(chan struct{}),

		logger: logger.With("peer", remote.Id),
	}
}

var errPeeringStop = errors.New("peering stopped")

func (p *directPeer) run(ctx context.Context) {
	defer func() {
		active := p.local.removeActiveConns(p.remoteID)
		for _, conn := range active {
			defer conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_DirectConnectionClosed), "connection closed")
		}
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

func (p *directPeer) stop() {
	close(p.closer)
}

func (p *directPeer) runRemote(ctx context.Context) error {
	return p.remote.Listen(ctx, func(remote *pbs.ServerPeer) error {
		if p.local.isDirect() && (remote.Direct != nil || len(remote.Directs) > 0) {
			if p.incoming == nil {
				remoteClientCertBytes := remote.ClientCertificate
				if len(remoteClientCertBytes) == 0 {
					remoteClientCertBytes = remote.Direct.ClientCertificate
				}
				remoteClientCert, err := x509.ParseCertificate(remoteClientCertBytes)
				if err != nil {
					return fmt.Errorf("parse client certificate: %w", err)
				}
				p.incoming = newDirectPeerIncoming(ctx, p, remoteClientCert)
			}

			if p.outgoing == nil {
				remoteServerCertBytes := remote.ServerCertificate
				if len(remoteServerCertBytes) == 0 {
					remoteServerCertBytes = remote.Direct.ServerCertificate
				}
				remoteServerConf, err := newServerTLSConfig(remoteServerCertBytes)
				if err != nil {
					return fmt.Errorf("parse server certificate: %w", err)
				}

				directs := remote.Directs
				if len(directs) == 0 {
					directs = remote.Direct.Addresses
				}
				addrs := map[netip.AddrPort]struct{}{}
				for _, addr := range directs {
					addrs[addr.AsNetip()] = struct{}{}
				}
				p.outgoing = newDirectPeerOutgoing(ctx, p, remoteServerConf, addrs)
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

		var remotes remoteRelays
		for _, id := range remote.RelayIds {
			if remotes.ids == nil {
				remotes.ids = map[relayID]struct{}{}
			}
			remotes.ids[relayID(id)] = struct{}{}
		}
		for _, hp := range remote.Relays {
			if remotes.hps == nil {
				remotes.hps = map[model.HostPort]struct{}{}
			}
			remotes.hps[model.HostPortFromPB(hp)] = struct{}{}
		}

		switch {
		case p.relays == nil:
			p.relays = newDirectPeerRelays(ctx, p, remotes)
		case remotes.isEmpty():
			close(p.relays.closerCh)
			p.relays = nil
		default:
			p.relays.remotes.Set(remotes)
		}

		return nil
	})
}

var errClosed = errors.New("closed")

type directPeerIncoming struct {
	parent     *directPeer
	clientCert *x509.Certificate
	closer     chan struct{}
	logger     *slog.Logger
}

func newDirectPeerIncoming(ctx context.Context, parent *directPeer, clientCert *x509.Certificate) *directPeerIncoming {
	p := &directPeerIncoming{
		parent:     parent,
		clientCert: clientCert,
		closer:     make(chan struct{}),
		logger:     parent.logger.With("style", "incoming"),
	}
	go p.run(ctx)
	return p
}

func (p *directPeerIncoming) run(ctx context.Context) {
	boff := netc.MinBackoff
	for {
		conn, err := p.connect(ctx)
		if err != nil {
			p.logger.Debug("could not connect", "err", err)
			switch {
			case errors.Is(err, context.Canceled):
				return
			case errors.Is(err, errClosed):
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-p.closer:
				return
			case <-time.After(boff):
				boff = netc.NextBackoff(boff)
			}
			continue
		}
		boff = netc.MinBackoff

		if err := p.keepalive(ctx, conn); err != nil {
			p.logger.Debug("keepalive failed", "err", err)
			switch {
			case errors.Is(err, context.Canceled):
				return
			case errors.Is(err, errClosed):
				return
			}
		}
	}
}

func (p *directPeerIncoming) connect(ctx context.Context) (quic.Connection, error) {
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
		defer stream.Close()

		if _, err := pbc.ReadRequest(stream); err != nil {
			return nil, err
		} else if err := pb.Write(stream, &pbc.Response{}); err != nil {
			return nil, err
		}

		return conn, nil
	}
}

func (p *directPeerIncoming) keepalive(ctx context.Context, conn quic.Connection) error {
	defer conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_DirectKeepaliveClosed), "keepalive closed")

	p.parent.local.addActiveConn(p.parent.remoteID, peerIncoming, "", conn)
	defer p.parent.local.removeActiveConn(p.parent.remoteID, peerIncoming, "")

	quicc.RTTLogStats(conn, p.logger)
	for {
		select {
		case <-p.closer:
			return errClosed
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-conn.Context().Done():
			return context.Cause(conn.Context())
		case <-time.After(30 * time.Second):
			quicc.RTTLogStats(conn, p.logger)
		}
	}
}

type directPeerOutgoing struct {
	parent     *directPeer
	serverConf *serverTLSConfig
	addrs      map[netip.AddrPort]struct{}
	closer     chan struct{}
	logger     *slog.Logger
}

func newDirectPeerOutgoing(ctx context.Context, parent *directPeer, serverConfg *serverTLSConfig, addrs map[netip.AddrPort]struct{}) *directPeerOutgoing {
	p := &directPeerOutgoing{
		parent:     parent,
		serverConf: serverConfg,
		addrs:      addrs,
		closer:     make(chan struct{}),
		logger:     parent.logger.With("style", "outgoing"),
	}
	go p.run(ctx)
	return p
}

func (p *directPeerOutgoing) run(ctx context.Context) {
	boff := netc.MinBackoff
	for {
		conn, err := p.connect(ctx)
		if err != nil {
			p.logger.Debug("could not connect", "err", err)
			if errors.Is(err, context.Canceled) {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-p.closer:
				return
			case <-time.After(boff):
				boff = netc.NextBackoff(boff)
			}
			continue
		}
		boff = netc.MinBackoff

		if err := p.keepalive(ctx, conn); err != nil {
			p.logger.Debug("keepalive failed", "err", err)
			switch {
			case errors.Is(err, context.Canceled):
				return
			case errors.Is(err, errClosed):
				return
			}
		}
	}
}

func (p *directPeerOutgoing) connect(ctx context.Context) (quic.Connection, error) {
	var errs []error
	for paddr := range p.addrs {
		addr := net.UDPAddrFromAddrPort(paddr)

		p.logger.Debug("dialing direct", "addr", addr, "server", p.serverConf.name, "cert", p.serverConf.key)
		conn, err := p.parent.local.direct.transport.Dial(quicc.RTTContext(ctx), addr, &tls.Config{
			Certificates: []tls.Certificate{p.parent.local.clientCert},
			RootCAs:      p.serverConf.cas,
			ServerName:   p.serverConf.name,
			NextProtos:   model.ClientToClientNextProtos,
		}, quicc.StdConfig)
		switch {
		case errors.Is(err, context.Canceled):
			return nil, err
		case err != nil:
			errs = append(errs, err)
			continue
		}

		switch err := p.check(ctx, conn); {
		case errors.Is(err, context.Canceled):
			return nil, err
		case err != nil:
			conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_ConnectionCheckFailed), "connection check failed")
			errs = append(errs, err)
			continue
		}

		return conn, nil
	}
	return nil, errors.Join(errs...)
}

func (p *directPeerOutgoing) check(ctx context.Context, conn quic.Connection) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	if err := pb.Write(stream, &pbc.Request{}); err != nil {
		return err
	}
	if _, err := pbc.ReadResponse(stream); err != nil {
		return err
	}

	return nil
}

func (p *directPeerOutgoing) keepalive(ctx context.Context, conn quic.Connection) error {
	defer conn.CloseWithError(quic.ApplicationErrorCode(pb.Error_DirectKeepaliveClosed), "keepalive closed")

	p.parent.local.addActiveConn(p.parent.remoteID, peerOutgoing, "", conn)
	defer p.parent.local.removeActiveConn(p.parent.remoteID, peerOutgoing, "")

	quicc.RTTLogStats(conn, p.logger)
	for {
		select {
		case <-p.closer:
			return errClosed
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-conn.Context().Done():
			return context.Cause(conn.Context())
		case <-time.After(30 * time.Second):
			quicc.RTTLogStats(conn, p.logger)
		}
	}
}

type directPeerRelays struct {
	parent   *directPeer
	remotes  *notify.V[remoteRelays]
	closerCh chan struct{}
}

type remoteRelays struct { // TODO remove 0.10.0
	ids map[relayID]struct{}        // new remotes send relay ids
	hps map[model.HostPort]struct{} // old relays send hostports
}

func (r remoteRelays) isEmpty() bool { return len(r.ids) == 0 && len(r.hps) == 0 }

func newDirectPeerRelays(ctx context.Context, parent *directPeer, remotes remoteRelays) *directPeerRelays {
	if remotes.isEmpty() {
		return nil
	}
	p := &directPeerRelays{
		parent:   parent,
		remotes:  notify.New(remotes),
		closerCh: make(chan struct{}),
	}
	go p.run(ctx)
	return p
}

func (p *directPeerRelays) run(ctx context.Context) {
	var (
		locals  map[relayID]relayConn
		remotes remoteRelays
	)

	active := map[relayID]model.HostPort{}
	defer func() {
		for id := range active {
			p.parent.local.removeActiveConn(p.parent.remoteID, peerRelay, string(id))
		}
	}()

	update := func() {
		for id, hp := range active {
			_, relayed := locals[id]
			_, remoteByID := remotes.ids[id]
			_, remoteByHP := remotes.hps[hp]
			if !(relayed && (remoteByID || remoteByHP)) {
				p.parent.local.removeActiveConn(p.parent.remoteID, peerRelay, string(id))
				delete(active, id)
			}
		}

		for id := range remotes.ids {
			if conn, ok := locals[id]; ok {
				if _, ok := active[id]; !ok {
					p.parent.local.addActiveConn(p.parent.remoteID, peerRelay, string(id), conn.conn)
					active[id] = conn.hp
				}
			}
		}

		for hp := range remotes.hps {
			for id, conn := range locals {
				if conn.hp == hp {
					if _, ok := active[id]; !ok {
						p.parent.local.addActiveConn(p.parent.remoteID, peerRelay, string(id), conn.conn)
						active[id] = conn.hp
					}
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

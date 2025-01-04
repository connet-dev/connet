package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type directPeer struct {
	local *peer

	remoteId string
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

		remoteId: remote.Id,
		remote:   notify.New(remote),

		closer: make(chan struct{}),

		logger: logger.With("peer", remote.Id),
	}
}

var errPeeringStop = errors.New("peering stopped")

func (p *directPeer) run(ctx context.Context) {
	defer func() {
		active := p.local.removeActiveConns(p.remoteId)
		for _, conn := range active {
			conn.CloseWithError(1, "depeered")
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
		if p.local.isDirect() && remote.Direct != nil {
			if p.incoming == nil {
				remoteClientCert, err := x509.ParseCertificate(remote.Direct.ClientCertificate)
				if err != nil {
					return err
				}
				p.incoming = newDirectPeerIncoming(ctx, p, remoteClientCert)
			}

			if p.outgoing == nil {
				remoteServerConf, err := newServerTLSConfig(remote.Direct.ServerCertificate)
				if err != nil {
					return err
				}
				addrs := map[netip.AddrPort]struct{}{}
				for _, addr := range remote.Direct.Addresses {
					nip := addr.AsNetip()
					if p.local.restr.Accept(nip.Addr()) {
						addrs[nip] = struct{}{}
					}
				}
				if len(addrs) > 0 {
					p.outgoing = newDirectPeerOutgoing(ctx, p, remoteServerConf, addrs)
				}
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

		relays := map[model.HostPort]struct{}{}
		for _, relay := range remote.Relays {
			relays[model.HostPortFromPB(relay)] = struct{}{}
		}
		if p.relays == nil {
			p.relays = newDirectPeerRelays(ctx, p, relays)
		} else if len(relays) == 0 {
			close(p.relays.closerCh)
			p.relays = nil
		} else {
			p.relays.remotes.Set(relays)
		}

		return nil
	})
}

var errClosed = errors.New("closed")

type directPeerIncoming struct {
	parent     *directPeer
	clientCert *x509.Certificate
	closer     chan struct{}
}

func newDirectPeerIncoming(ctx context.Context, parent *directPeer, clientCert *x509.Certificate) *directPeerIncoming {
	p := &directPeerIncoming{
		parent:     parent,
		clientCert: clientCert,
		closer:     make(chan struct{}),
	}
	go p.run(ctx)
	return p
}

func (p *directPeerIncoming) run(ctx context.Context) {
	boff := netc.MinBackoff
	for {
		conn, stream, err := p.connect(ctx)
		if err != nil {
			p.parent.logger.Debug("could not connect incoming", "err", err)
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

		if err := p.keepalive(ctx, conn, stream); err != nil {
			p.parent.logger.Debug("incoming keepalive failed", "err", err)
			switch {
			case errors.Is(err, context.Canceled):
				return
			case errors.Is(err, errClosed):
				return
			}
		}
	}
}

func (p *directPeerIncoming) connect(ctx context.Context) (quic.Connection, quic.Stream, error) {
	ch, cancel := p.parent.local.direct.expect(p.parent.local.serverCert, p.clientCert)
	select {
	case <-ctx.Done():
		cancel()
		return nil, nil, ctx.Err()
	case <-p.closer:
		cancel()
		return nil, nil, errClosed
	case conn := <-ch:
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return nil, nil, err
		}
		if err := p.heartbeat(stream); err != nil {
			return nil, nil, err
		}
		return conn, stream, nil
	}
}

func (p *directPeerIncoming) keepalive(ctx context.Context, conn quic.Connection, stream quic.Stream) error {
	defer conn.CloseWithError(1, "disconnected")
	defer stream.Close()

	p.parent.local.addActiveConn(p.parent.remoteId, peerIncoming, "", conn)
	defer p.parent.local.removeActiveConn(p.parent.remoteId, peerIncoming, "")

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.closer:
			return errClosed
		}
	})

	g.Go(func() error {
		for {
			if err := p.heartbeat(stream); err != nil {
				return err
			}
		}
	})

	return g.Wait()
}

func (p *directPeerIncoming) heartbeat(stream quic.Stream) error {
	req, err := pbc.ReadRequest(stream)
	switch {
	case err != nil:
		return err
	case req.Heartbeat == nil:
		respErr := pb.NewError(pb.Error_RequestUnknown, "unexpected request")
		if err := pb.Write(stream, &pbc.Response{Error: respErr}); err != nil {
			return kleverr.Ret(err)
		}
		return respErr
	}

	return pb.Write(stream, &pbc.Response{Heartbeat: req.Heartbeat})
}

type directPeerOutgoing struct {
	parent     *directPeer
	serverConf *serverTLSConfig
	addrs      map[netip.AddrPort]struct{}
	closer     chan struct{}
}

func newDirectPeerOutgoing(ctx context.Context, parent *directPeer, serverConfg *serverTLSConfig, addrs map[netip.AddrPort]struct{}) *directPeerOutgoing {
	p := &directPeerOutgoing{
		parent:     parent,
		serverConf: serverConfg,
		addrs:      addrs,
		closer:     make(chan struct{}),
	}
	go p.run(ctx)
	return p
}

func (p *directPeerOutgoing) run(ctx context.Context) {
	boff := netc.MinBackoff
	for {
		conn, stream, err := p.connect(ctx)
		if err != nil {
			p.parent.logger.Debug("could not connect direct", "err", err)
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

		if err := p.keepalive(ctx, conn, stream); err != nil {
			p.parent.logger.Debug("disonnected peer", "err", err)
			switch {
			case errors.Is(err, context.Canceled):
				return
			case errors.Is(err, errClosed):
				return
			}
		}
	}
}

func (p *directPeerOutgoing) connect(ctx context.Context) (quic.Connection, quic.Stream, error) {
	var errs []error
	for paddr := range p.addrs {
		addr := net.UDPAddrFromAddrPort(paddr)

		p.parent.logger.Debug("dialing direct", "addr", addr, "server", p.serverConf.name, "cert", p.serverConf.key)
		conn, err := p.parent.local.direct.transport.Dial(ctx, addr, &tls.Config{
			Certificates: []tls.Certificate{p.parent.local.clientCert},
			RootCAs:      p.serverConf.cas,
			ServerName:   p.serverConf.name,
			NextProtos:   []string{"connet-direct"},
		}, &quic.Config{
			KeepAlivePeriod: 25 * time.Second,
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := p.heartbeat(ctx, stream); err != nil {
			errs = append(errs, err)
			continue
		}
		return conn, stream, nil
	}
	return nil, nil, errors.Join(errs...)
}

func (p *directPeerOutgoing) keepalive(ctx context.Context, conn quic.Connection, stream quic.Stream) error {
	defer conn.CloseWithError(1, "disconnected")
	defer stream.Close()

	p.parent.local.addActiveConn(p.parent.remoteId, peerOutgoing, "", conn)
	defer p.parent.local.removeActiveConn(p.parent.remoteId, peerOutgoing, "")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.closer:
			return errClosed
		case <-time.After(10 * time.Second):
		}
		if err := p.heartbeat(ctx, stream); err != nil {
			return err
		}
	}
}

func (p *directPeerOutgoing) heartbeat(ctx context.Context, stream quic.Stream) error {
	// TODO setDeadline as additional assurance we are not blocked
	req := &pbc.Heartbeat{Time: timestamppb.Now()}
	if err := pb.Write(stream, &pbc.Request{Heartbeat: req}); err != nil {
		return err
	}
	if resp, err := pbc.ReadResponse(stream); err != nil {
		return err
	} else {
		dur := time.Since(resp.Heartbeat.Time.AsTime())
		p.parent.logger.Debug("direct heartbeat", "dur", dur)
		return nil
	}
}

type directPeerRelays struct {
	parent   *directPeer
	remotes  *notify.V[map[model.HostPort]struct{}]
	closerCh chan struct{}
}

func newDirectPeerRelays(ctx context.Context, parent *directPeer, remotes map[model.HostPort]struct{}) *directPeerRelays {
	if len(remotes) == 0 {
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
		relays map[model.HostPort]quic.Connection
		remote map[model.HostPort]struct{}
	)

	var active = map[model.HostPort]struct{}{}
	defer func() {
		for hp := range active {
			p.parent.local.removeActiveConn(p.parent.remoteId, peerRelay, hp.String())
		}
	}()

	var update = func() {
		for hp := range active {
			_, relayed := relays[hp]
			_, remoted := remote[hp]
			if !(relayed && remoted) {
				p.parent.local.removeActiveConn(p.parent.remoteId, peerRelay, hp.String())
				delete(active, hp)
			}
		}

		for hp := range remote {
			if conn := relays[hp]; conn != nil {
				if _, ok := active[hp]; !ok {
					p.parent.local.addActiveConn(p.parent.remoteId, peerRelay, hp.String(), conn)
					active[hp] = struct{}{}
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
		case relays = <-relaysCh:
			update()
		case remote = <-remoteCh:
			update()
		}
	}
}

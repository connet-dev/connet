package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pbs"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

type directPeer struct {
	local *peer

	remoteId       string
	remote         *notify.V[*pbs.ServerPeer]
	directIncoming *notify.V[*x509.Certificate]
	directOutgoing *notify.V[*directPeerOutgoing]
	relays         *notify.V[map[model.HostPort]struct{}]

	closer chan struct{}

	logger *slog.Logger
}

type directPeerOutgoing struct {
	serverConf *serverTLSConfig
	addrs      map[netip.AddrPort]struct{}
}

func newPeering(local *peer, remote *pbs.ServerPeer, logger *slog.Logger) *directPeer {
	p := &directPeer{
		local: local,

		remoteId:       remote.Id,
		remote:         notify.NewV[*pbs.ServerPeer](),
		directIncoming: notify.NewV[*x509.Certificate](),
		directOutgoing: notify.NewV[*directPeerOutgoing](),
		relays:         notify.NewV(notify.CopyMapOpt[map[model.HostPort]struct{}]()),

		closer: make(chan struct{}),

		logger: logger.With("peering", remote.Id),
	}
	p.remote.Set(remote)
	return p
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
	g.Go(func() error { return p.runDirectIncoming(ctx) })
	g.Go(func() error { return p.runDirectOutgoing(ctx) })
	g.Go(func() error { return p.runRelay(ctx) })
	g.Go(func() error {
		<-p.closer
		return errPeeringStop
	})

	if err := g.Wait(); err != nil {
		p.logger.Warn("error while running peering", "err", err)
	}
}

func (p *directPeer) stop() {
	close(p.closer)
}

func (p *directPeer) runRemote(ctx context.Context) error {
	return p.remote.Listen(ctx, func(remote *pbs.ServerPeer) error {
		if remote.Direct != nil {
			remoteClientCert, err := x509.ParseCertificate(remote.Direct.ClientCertificate)
			if err != nil {
				return err
			}
			p.directIncoming.Set(remoteClientCert)

			remoteServerConf, err := newServerTLSConfig(remote.Direct.ServerCertificate)
			if err != nil {
				return err
			}
			addrs := map[netip.AddrPort]struct{}{}
			for _, addr := range remote.Direct.Addresses {
				addrs[addr.AsNetip()] = struct{}{}
			}
			p.directOutgoing.Set(&directPeerOutgoing{
				remoteServerConf,
				addrs,
			})
		}

		relays := map[model.HostPort]struct{}{}
		for _, relay := range remote.Relays {
			relays[model.NewHostPortFromPB(relay)] = struct{}{}
		}
		p.relays.Set(relays)

		return nil
	})
}

func (p *directPeer) runDirectIncoming(ctx context.Context) error {
	return p.directIncoming.Listen(ctx, func(clientCert *x509.Certificate) error {
		if p.local.hasActiveConn(p.remoteId, peerIncoming, "") {
			return nil
		}

		ch := p.local.direct.expectConn(p.local.serverCert, clientCert)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case conn, ok := <-ch:
			if ok {
				p.local.addActiveConn(p.remoteId, peerIncoming, "", conn)
			}
			return nil
		}
	})
}

func (p *directPeer) runDirectOutgoing(ctx context.Context) error {
	return p.directOutgoing.Listen(ctx, func(out *directPeerOutgoing) error {
		if p.local.hasActiveConn(p.remoteId, peerOutgoing, "") {
			return nil
		}

		// TODO retry direct outgong conns to accomodate for network instability and NAT behavior
		for paddr := range out.addrs {
			addr := net.UDPAddrFromAddrPort(paddr)

			p.logger.Debug("dialing direct", "addr", addr, "server", out.serverConf.name, "cert", out.serverConf.key)
			conn, err := p.local.direct.transport.Dial(ctx, addr, &tls.Config{
				Certificates: []tls.Certificate{p.local.clientCert},
				RootCAs:      out.serverConf.cas,
				ServerName:   out.serverConf.name,
				NextProtos:   []string{"connet-direct"},
			}, &quic.Config{
				KeepAlivePeriod: 25 * time.Second,
			})
			if err != nil {
				p.logger.Debug("could not dial direct", "addr", addr, "err", err)
				continue
			}
			p.local.addActiveConn(p.remoteId, peerOutgoing, "", conn)
			break
		}
		return nil
	})
}

func (p *directPeer) runRelay(ctx context.Context) error {
	var updateMu sync.Mutex
	var update = func(local map[model.HostPort]quic.Connection, remote map[model.HostPort]struct{}) error {
		updateMu.Lock()
		defer updateMu.Unlock()

		for hp := range remote {
			if conn := local[hp]; conn != nil {
				// exists in both, so it is active
				p.local.addActiveConn(p.remoteId, peerRelay, hp.String(), conn)
			} else {
				// remote reports it is connected, but we are not
				p.local.removeActiveConn(p.remoteId, peerRelay, hp.String())
			}
		}

		for hp := range local {
			if _, ok := remote[hp]; !ok {
				// local connected, but not the remote
				p.local.removeActiveConn(p.remoteId, peerRelay, hp.String())
			}
		}

		return nil
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return p.local.activeRelayConns.Listen(ctx, func(local map[model.HostPort]quic.Connection) error {
			p.logger.Debug("update local relays", "len", len(local))
			return update(local, p.relays.Get())
		})
	})

	g.Go(func() error {
		return p.relays.Listen(ctx, func(relays map[model.HostPort]struct{}) error {
			p.logger.Debug("update peer relays", "len", len(relays))
			return update(p.local.activeRelayConns.Get(), relays)
		})
	})

	return g.Wait()
}

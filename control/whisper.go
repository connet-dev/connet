package control

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
	"github.com/keihaya-com/connet/pbs"
	"github.com/segmentio/ksuid"
)

type whisperer struct {
	whispers map[model.Forward]*whisper
	mu       sync.RWMutex
}

func newWhisperer() *whisperer {
	return &whisperer{
		whispers: map[model.Forward]*whisper{},
	}
}

func (w *whisperer) For(fwd model.Forward) *whisper {
	w.mu.RLock()
	wh := w.whispers[fwd]
	w.mu.RUnlock()
	if wh != nil {
		return wh
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	wh = w.whispers[fwd]
	if wh != nil {
		return wh
	}

	wh = &whisper{
		forward: fwd,
		destinations: notify.NewV(notify.InitialOpt(map[ksuid.KSUID]*pbs.ServerPeer{}),
			notify.CopyMapOpt[map[ksuid.KSUID]*pbs.ServerPeer]()),
		sources: notify.NewV(notify.InitialOpt(map[ksuid.KSUID]*pbs.ServerPeer{}),
			notify.CopyMapOpt[map[ksuid.KSUID]*pbs.ServerPeer]()),
	}
	w.whispers[fwd] = wh
	return wh
}

type whisper struct {
	forward      model.Forward
	destinations *notify.V[map[ksuid.KSUID]*pbs.ServerPeer]
	sources      *notify.V[map[ksuid.KSUID]*pbs.ServerPeer]
}

func (w *whisper) AddDestination(id ksuid.KSUID, peer *pbs.ClientPeer) {
	w.destinations.Modify(func(m map[ksuid.KSUID]*pbs.ServerPeer) {
		m[id] = &pbs.ServerPeer{
			Id:     id.String(),
			Direct: peer.Direct,
			Relays: peer.Relays,
		}
	})
}

func (w *whisper) RemoveDestination(id ksuid.KSUID) {
	w.destinations.Modify(func(m map[ksuid.KSUID]*pbs.ServerPeer) {
		delete(m, id)
	})
}

func (w *whisper) Destinations(ctx context.Context, f func([]*pbs.ServerPeer) error) error {
	return w.destinations.Listen(ctx, func(t map[ksuid.KSUID]*pbs.ServerPeer) error {
		vals := slices.Collect(maps.Values(t))
		return f(vals)
	})
}

func (w *whisper) AddSource(id ksuid.KSUID, peer *pbs.ClientPeer) {
	w.sources.Modify(func(m map[ksuid.KSUID]*pbs.ServerPeer) {
		m[id] = &pbs.ServerPeer{
			Id:     id.String(),
			Direct: peer.Direct,
			Relays: peer.Relays,
		}
	})
}

func (w *whisper) RemoveSource(id ksuid.KSUID) {
	w.sources.Modify(func(m map[ksuid.KSUID]*pbs.ServerPeer) {
		delete(m, id)
	})
}

func (w *whisper) Sources(ctx context.Context, f func([]*pbs.ServerPeer) error) error {
	return w.sources.Listen(ctx, func(t map[ksuid.KSUID]*pbs.ServerPeer) error {
		vals := slices.Collect(maps.Values(t))
		return f(vals)
	})
}

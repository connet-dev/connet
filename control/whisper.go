package control

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/keihaya-com/connet/logc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pbs"
	"github.com/segmentio/ksuid"
)

type whisperer struct {
	whispers map[model.Forward]*whisper
	mu       sync.RWMutex
}

type whisper struct {
	forward model.Forward
	dsts    logc.KV[ksuid.KSUID, *pbs.ServerPeer]
	srcs    logc.KV[ksuid.KSUID, *pbs.ServerPeer]
}

func newWhisperer() *whisperer {
	return &whisperer{
		whispers: map[model.Forward]*whisper{},
	}
}

func (w *whisperer) get(fwd model.Forward) *whisper {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return w.whispers[fwd]
}

func (w *whisperer) create(fwd model.Forward) *whisper {
	if wh := w.get(fwd); wh != nil {
		return wh
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if wh := w.whispers[fwd]; wh != nil {
		return wh
	}

	wh := &whisper{
		forward: fwd,
		dsts:    logc.NewMemoryKVLog[ksuid.KSUID, *pbs.ServerPeer](),
		srcs:    logc.NewMemoryKVLog[ksuid.KSUID, *pbs.ServerPeer](),
	}
	w.whispers[fwd] = wh
	return wh
}

func (w *whisperer) AddDestination(fwd model.Forward, id ksuid.KSUID, peer *pbs.ClientPeer) {
	wh := w.create(fwd)
	wh.dsts.Put(id, &pbs.ServerPeer{
		Id:     id.String(),
		Direct: peer.Direct,
		Relays: peer.Relays,
	})
}

func (w *whisperer) RemoveDestination(fwd model.Forward, id ksuid.KSUID) {
	wh := w.get(fwd)
	wh.dsts.Del(id)
}

func (w *whisperer) Destinations(ctx context.Context, fwd model.Forward, f func([]*pbs.ServerPeer) error) error {
	wh := w.get(fwd)
	return wh.dsts.Listen(ctx, func(m map[ksuid.KSUID]*pbs.ServerPeer) error {
		vals := slices.Collect(maps.Values(m))
		return f(vals)
	})
}

func (w *whisperer) AddSource(fwd model.Forward, id ksuid.KSUID, peer *pbs.ClientPeer) {
	wh := w.create(fwd)
	wh.srcs.Put(id, &pbs.ServerPeer{
		Id:     id.String(),
		Direct: peer.Direct,
		Relays: peer.Relays,
	})
}

func (w *whisperer) RemoveSource(fwd model.Forward, id ksuid.KSUID) {
	wh := w.get(fwd)
	wh.srcs.Del(id)
}

func (w *whisperer) Sources(ctx context.Context, fwd model.Forward, f func([]*pbs.ServerPeer) error) error {
	wh := w.get(fwd)
	return wh.srcs.Listen(ctx, func(m map[ksuid.KSUID]*pbs.ServerPeer) error {
		vals := slices.Collect(maps.Values(m))
		return f(vals)
	})
}

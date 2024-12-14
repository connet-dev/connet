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
		dsts:    logc.NewMemoryKVLog[ksuid.KSUID, *pbs.ServerPeer](),
		srcs:    logc.NewMemoryKVLog[ksuid.KSUID, *pbs.ServerPeer](),
	}
	w.whispers[fwd] = wh
	return wh
}

type whisper struct {
	forward model.Forward
	dsts    logc.KV[ksuid.KSUID, *pbs.ServerPeer]
	srcs    logc.KV[ksuid.KSUID, *pbs.ServerPeer]
}

func (w *whisper) AddDestination(id ksuid.KSUID, peer *pbs.ClientPeer) {
	w.dsts.Put(id, &pbs.ServerPeer{
		Id:     id.String(),
		Direct: peer.Direct,
		Relays: peer.Relays,
	})
}

func (w *whisper) RemoveDestination(id ksuid.KSUID) {
	w.dsts.Del(id)
}

func (w *whisper) Destinations(ctx context.Context, f func([]*pbs.ServerPeer) error) error {
	return w.dsts.Listen(ctx, func(m map[ksuid.KSUID]*pbs.ServerPeer) error {
		vals := slices.Collect(maps.Values(m))
		return f(vals)
	})
}

func (w *whisper) AddSource(id ksuid.KSUID, peer *pbs.ClientPeer) {
	w.srcs.Put(id, &pbs.ServerPeer{
		Id:     id.String(),
		Direct: peer.Direct,
		Relays: peer.Relays,
	})
}

func (w *whisper) RemoveSource(id ksuid.KSUID) {
	w.srcs.Del(id)
}

func (w *whisper) Sources(ctx context.Context, f func([]*pbs.ServerPeer) error) error {
	return w.srcs.Listen(ctx, func(m map[ksuid.KSUID]*pbs.ServerPeer) error {
		vals := slices.Collect(maps.Values(m))
		return f(vals)
	})
}

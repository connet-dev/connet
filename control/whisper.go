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
		forward:            fwd,
		destinations:       map[ksuid.KSUID]*pbs.ServerPeer{},
		destinationsNotify: notify.New(),
		sources:            map[ksuid.KSUID]*pbs.ServerPeer{},
		sourcesNotify:      notify.New(),
	}
	w.whispers[fwd] = wh
	return wh
}

type whisper struct {
	forward            model.Forward
	destinations       map[ksuid.KSUID]*pbs.ServerPeer
	destinationsMu     sync.RWMutex
	destinationsNotify *notify.N
	sources            map[ksuid.KSUID]*pbs.ServerPeer
	sourcesMu          sync.RWMutex
	sourcesNotify      *notify.N
}

func (w *whisper) AddDestination(id ksuid.KSUID, peer *pbs.ClientPeer) {
	defer w.destinationsNotify.Updated()

	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	w.destinations[id] = &pbs.ServerPeer{
		Id:     id.String(),
		Direct: peer.Direct,
		Relays: peer.Relays,
	}
}

func (w *whisper) RemoveDestination(id ksuid.KSUID) {
	defer w.destinationsNotify.Updated()

	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	delete(w.destinations, id)
}

func (w *whisper) getDestinations() []*pbs.ServerPeer {
	w.destinationsMu.RLock()
	defer w.destinationsMu.RUnlock()

	return slices.Collect(maps.Values(w.destinations))
}

func (w *whisper) Destinations(ctx context.Context, f func([]*pbs.ServerPeer) error) error {
	return w.destinationsNotify.Listen(ctx, func() error {
		return f(w.getDestinations())
	})
}

func (w *whisper) AddSource(id ksuid.KSUID, peer *pbs.ClientPeer) {
	defer w.sourcesNotify.Updated()

	w.sourcesMu.Lock()
	defer w.sourcesMu.Unlock()

	w.sources[id] = &pbs.ServerPeer{
		Id:     id.String(),
		Direct: peer.Direct,
		Relays: peer.Relays,
	}
}

func (w *whisper) RemoveSource(id ksuid.KSUID) {
	defer w.sourcesNotify.Updated()

	w.sourcesMu.Lock()
	defer w.sourcesMu.Unlock()

	delete(w.sources, id)
}

func (w *whisper) getSources() []*pbs.ServerPeer {
	w.sourcesMu.RLock()
	defer w.sourcesMu.RUnlock()

	return slices.Collect(maps.Values(w.sources))
}

func (w *whisper) Sources(ctx context.Context, f func([]*pbs.ServerPeer) error) error {
	return w.sourcesNotify.Listen(ctx, func() error {
		return f(w.getSources())
	})
}

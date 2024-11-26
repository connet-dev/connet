package control

import (
	"context"
	"crypto/x509"
	"sync"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/notify"
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
		destinations:       map[ksuid.KSUID]*whisperDestination{},
		destinationsNotify: notify.New(),
		sources:            map[ksuid.KSUID]*whisperSource{},
		sourcesNotify:      notify.New(),
	}
	w.whispers[fwd] = wh
	return wh
}

type whisper struct {
	forward            model.Forward
	destinations       map[ksuid.KSUID]*whisperDestination
	destinationsMu     sync.RWMutex
	destinationsNotify *notify.N
	sources            map[ksuid.KSUID]*whisperSource
	sourcesMu          sync.RWMutex
	sourcesNotify      *notify.N
}

type whisperDestination struct {
	directs []model.Route
	relays  []model.Route
}

type whisperSource struct {
	cert *x509.Certificate
}

func (w *whisper) AddDestination(id ksuid.KSUID, directs []model.Route, relays []model.Route) {
	defer w.destinationsNotify.Updated()

	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	w.destinations[id] = &whisperDestination{
		directs: directs,
		relays:  relays,
	}
}

func (w *whisper) RemoveDestination(id ksuid.KSUID) {
	defer w.destinationsNotify.Updated()

	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	delete(w.destinations, id)
}

func (w *whisper) AddSource(id ksuid.KSUID, cert *x509.Certificate) {
	defer w.sourcesNotify.Updated()

	w.sourcesMu.Lock()
	defer w.sourcesMu.Unlock()

	w.sources[id] = &whisperSource{
		cert: cert,
	}
}

func (w *whisper) RemoveSource(id ksuid.KSUID) {
	defer w.sourcesNotify.Updated()

	w.sourcesMu.Lock()
	defer w.sourcesMu.Unlock()

	delete(w.sources, id)
}

func (w *whisper) Sources() []*x509.Certificate {
	w.sourcesMu.RLock()
	defer w.sourcesMu.RUnlock()

	var result []*x509.Certificate
	for _, src := range w.sources {
		result = append(result, src.cert)
	}

	return result
}

func (w *whisper) SourcesListen(ctx context.Context, f func([]*x509.Certificate) error) error {
	return w.sourcesNotify.Listen(ctx, func() error {
		return f(w.Sources())
	})
}

func (w *whisper) Destinations() ([]model.Route, []model.Route) {
	w.destinationsMu.RLock()
	defer w.destinationsMu.RUnlock()

	var directs []model.Route
	var relays []model.Route

	for _, dst := range w.destinations {
		directs = append(directs, dst.directs...)
		relays = append(relays, dst.relays...)
	}

	return directs, relays
}

func (w *whisper) DestinationsListen(ctx context.Context, f func([]model.Route, []model.Route) error) error {
	return w.destinationsNotify.Listen(ctx, func() error {
		return f(w.Destinations())
	})
}

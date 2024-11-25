package connet

import (
	"context"
	"crypto/x509"
	"sync"

	"github.com/segmentio/ksuid"
)

type Whispers struct {
	whisperers map[Forward]*Whisperer
	mu         sync.RWMutex
}

func NewWhispers() *Whispers {
	return &Whispers{
		whisperers: map[Forward]*Whisperer{},
	}
}

func (w *Whispers) For(fwd Forward) *Whisperer {
	w.mu.RLock()
	wh := w.whisperers[fwd]
	w.mu.RUnlock()
	if wh != nil {
		return wh
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	wh = w.whisperers[fwd]
	if wh != nil {
		return wh
	}

	wh = &Whisperer{
		forward:            fwd,
		destinations:       map[ksuid.KSUID]*whisperDestination{},
		destinationsNotify: newNotify(),
		sources:            map[ksuid.KSUID]*whisperSource{},
		sourcesNotify:      newNotify(),
	}
	w.whisperers[fwd] = wh
	return wh
}

type Whisperer struct {
	forward            Forward
	destinations       map[ksuid.KSUID]*whisperDestination
	destinationsMu     sync.RWMutex
	destinationsNotify *notify
	sources            map[ksuid.KSUID]*whisperSource
	sourcesMu          sync.RWMutex
	sourcesNotify      *notify
}

type whisperDestination struct {
	directs []Route
	relays  []Route
}

type whisperSource struct {
	cert *x509.Certificate
}

func (w *Whisperer) AddDestination(id ksuid.KSUID, directs []Route, relays []Route) {
	defer w.destinationsNotify.inc()

	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	w.destinations[id] = &whisperDestination{
		directs: directs,
		relays:  relays,
	}
}

func (w *Whisperer) RemoveDestination(id ksuid.KSUID) {
	defer w.destinationsNotify.inc()

	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	delete(w.destinations, id)
}

func (w *Whisperer) AddSource(id ksuid.KSUID, cert *x509.Certificate) {
	defer w.sourcesNotify.inc()

	w.sourcesMu.Lock()
	defer w.sourcesMu.Unlock()

	w.sources[id] = &whisperSource{
		cert: cert,
	}
}

func (w *Whisperer) RemoveSource(id ksuid.KSUID) {
	defer w.sourcesNotify.inc()

	w.sourcesMu.Lock()
	defer w.sourcesMu.Unlock()

	delete(w.sources, id)
}

func (w *Whisperer) Sources() []*x509.Certificate {
	w.sourcesMu.RLock()
	defer w.sourcesMu.RUnlock()

	var result []*x509.Certificate
	for _, src := range w.sources {
		result = append(result, src.cert)
	}

	return result
}

func (w *Whisperer) SourcesNotify(ctx context.Context, f func([]*x509.Certificate) error) error {
	return runNotify(ctx, w.sourcesNotify, func() error {
		return f(w.Sources())
	})
}

func (w *Whisperer) Destinations() ([]Route, []Route) {
	w.destinationsMu.RLock()
	defer w.destinationsMu.RUnlock()

	var directs []Route
	var relays []Route

	for _, dst := range w.destinations {
		directs = append(directs, dst.directs...)
		relays = append(relays, dst.relays...)
	}

	return directs, relays
}

func (w *Whisperer) DestinationsNotify(ctx context.Context, f func([]Route, []Route) error) error {
	return runNotify(ctx, w.destinationsNotify, func() error {
		return f(w.Destinations())
	})
}

type Route struct {
	Hostport    string
	Certificate *x509.Certificate
}

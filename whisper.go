package connet

import (
	"context"
	"crypto/x509"
	"net/netip"
	"sync"

	"github.com/segmentio/ksuid"
)

type Whispers struct {
	whisperers map[Binding]*Whisperer
	mu         sync.RWMutex
}

func NewWhispers() *Whispers {
	return &Whispers{
		whisperers: map[Binding]*Whisperer{},
	}
}

func (w *Whispers) For(bind Binding) *Whisperer {
	w.mu.RLock()
	wh := w.whisperers[bind]
	w.mu.RUnlock()
	if wh != nil {
		return wh
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	wh = w.whisperers[bind]
	if wh != nil {
		return wh
	}

	wh = &Whisperer{
		bind:               bind,
		destinations:       map[ksuid.KSUID]*whisperDestination{},
		destinationsNotify: newNotify(),
		sources:            map[ksuid.KSUID]*whisperSource{},
		sourcesNotify:      newNotify(),
	}
	w.whisperers[bind] = wh
	return wh
}

type Whisperer struct {
	bind Binding

	destinations       map[ksuid.KSUID]*whisperDestination
	destinationsMu     sync.RWMutex
	destinationsNotify *notify
	sources            map[ksuid.KSUID]*whisperSource
	sourcesMu          sync.RWMutex
	sourcesNotify      *notify
}

type whisperDestination struct {
	direct *DirectDestination
	relays []RelayDestination
}

type whisperSource struct {
	cert *x509.Certificate
}

func (w *Whisperer) AddDestination(id ksuid.KSUID, direct *DirectDestination, relays []RelayDestination) {
	defer w.destinationsNotify.inc()

	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	w.destinations[id] = &whisperDestination{
		direct: direct,
		relays: relays,
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

func (w *Whisperer) Destinations() ([]DirectDestination, []RelayDestination) {
	w.destinationsMu.RLock()
	defer w.destinationsMu.RUnlock()

	var direct []DirectDestination
	var relays []RelayDestination

	for _, dst := range w.destinations {
		if dst.direct != nil {
			direct = append(direct, *dst.direct)
		}
		relays = append(relays, dst.relays...)
	}

	return direct, relays
}

func (w *Whisperer) DestinationsNotify(ctx context.Context, f func([]DirectDestination, []RelayDestination) error) error {
	return runNotify(ctx, w.destinationsNotify, func() error {
		return f(w.Destinations())
	})
}

type DirectDestination struct {
	Addresses   []netip.AddrPort
	Certificate *x509.Certificate
}

type RelayDestination struct {
	Hostport string
}

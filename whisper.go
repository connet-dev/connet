package connet

import (
	"crypto/sha256"
	"crypto/x509"
	"net/netip"
	"sync"
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
		bind:         bind,
		destinations: map[[sha256.Size]byte]*whisperDestination{},
		sources:      map[[sha256.Size]byte]*whisperSource{},
	}
	w.whisperers[bind] = wh
	return wh
}

type Whisperer struct {
	bind Binding

	destinations   map[[sha256.Size]byte]*whisperDestination
	destinationsMu sync.RWMutex
	sources        map[[sha256.Size]byte]*whisperSource
	sourcesMu      sync.RWMutex
}

type whisperDestination struct {
	cert   *x509.Certificate
	direct []netip.AddrPort
	relay  []netip.AddrPort
}

type whisperSource struct {
	cert *x509.Certificate
}

func (w *Whisperer) AddDestination(directCert *x509.Certificate, directAddrs, relayAddrs []netip.AddrPort) {
	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	w.destinations[sha256.Sum256(directCert.Raw)] = &whisperDestination{
		cert:   directCert,
		direct: directAddrs,
		relay:  relayAddrs,
	}
}

func (w *Whisperer) RemoveDestination(cert *x509.Certificate) {
	w.destinationsMu.Lock()
	defer w.destinationsMu.Unlock()

	delete(w.destinations, sha256.Sum256(cert.Raw))
}

func (w *Whisperer) AddSource(cert *x509.Certificate) {
	w.sourcesMu.Lock()
	defer w.sourcesMu.Unlock()

	w.sources[sha256.Sum256(cert.Raw)] = &whisperSource{
		cert: cert,
	}
}

func (w *Whisperer) RemoveSource(cert *x509.Certificate) {
	w.sourcesMu.Lock()
	defer w.sourcesMu.Unlock()

	delete(w.sources, sha256.Sum256(cert.Raw))
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

func (w *Whisperer) Destinations() DestinationsUpdate {
	w.destinationsMu.RLock()
	defer w.destinationsMu.RUnlock()

	var clients []DestinationsClient
	var relays []netip.AddrPort

	for _, dst := range w.destinations {
		clients = append(clients, DestinationsClient{
			Certificate: dst.cert,
			Addresses:   dst.direct,
		})
		relays = append(relays, dst.relay...)
	}

	return DestinationsUpdate{
		Clients: clients,
		Relays:  relays,
	}
}

type DestinationsUpdate struct {
	Clients []DestinationsClient
	Relays  []netip.AddrPort
}

type DestinationsClient struct {
	Certificate *x509.Certificate
	Addresses   []netip.AddrPort
}

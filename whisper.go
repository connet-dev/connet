package connet

import (
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

	wh = &Whisperer{bind}
	w.whisperers[bind] = wh
	return wh
}

type Whisperer struct {
	bind Binding
}

func (w *Whisperer) AddDestination(directCert *x509.Certificate, directAddrs, relayAddrs []netip.AddrPort) {

}

func (w *Whisperer) RemoveDestination(cert *x509.Certificate) {

}

func (w *Whisperer) AddSource(cert *x509.Certificate) {

}

func (w *Whisperer) RemoveSource(cert *x509.Certificate) {

}

func (w *Whisperer) Sources() []*x509.Certificate {
	return nil
}

func (w *Whisperer) Destinations() DestinationsUpdate {
	return DestinationsUpdate{}
}

type DestinationsUpdate struct {
	Clients []DestinationsClient
	Relays  []netip.AddrPort
}

type DestinationsClient struct {
	Certificate *x509.Certificate
	Addresses   []netip.AddrPort
}

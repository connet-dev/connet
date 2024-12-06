package control

import (
	"context"
	"crypto/x509"

	"github.com/keihaya-com/connet/model"
)

type Relays interface {
	AddDestination(fwd model.Forward, cert *x509.Certificate) (*x509.Certificate, error)
	RemoveDestination(fwd model.Forward, cert *x509.Certificate)

	AddSource(fwd model.Forward, cert *x509.Certificate) (*x509.Certificate, error)
	RemoveSource(fwd model.Forward, cert *x509.Certificate)

	Active(ctx context.Context, f func(addrs map[model.HostPort]struct{}) error) error
}

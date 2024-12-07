package control

import (
	"context"
	"crypto/x509"

	"github.com/keihaya-com/connet/model"
)

type Relays interface {
	Destination(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
		notify func(map[model.HostPort]*x509.Certificate) error) error
	Source(ctx context.Context, fwd model.Forward, cert *x509.Certificate,
		notify func(map[model.HostPort]*x509.Certificate) error) error
}

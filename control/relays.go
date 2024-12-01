package control

import (
	"context"
	"crypto/x509"

	"github.com/keihaya-com/connet/model"
)

type Relays interface {
	Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward)
	Remove(cert *x509.Certificate)

	Active(ctx context.Context, f func(addrs map[model.HostPort]*x509.Certificate) error) error
}

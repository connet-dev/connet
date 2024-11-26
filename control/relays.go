package control

import (
	"context"
	"crypto/x509"

	"github.com/keihaya-com/connet/model"
)

type Relays interface {
	Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward)
	Remove(cert *x509.Certificate)

	Active() []string
	ActiveNotify(ctx context.Context, f func(hostports []string) error) error
}

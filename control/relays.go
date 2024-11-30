package control

import (
	"context"
	"crypto/x509"
	"net/netip"

	"github.com/keihaya-com/connet/model"
)

type Relays interface {
	Add(cert *x509.Certificate, destinations []model.Forward, sources []model.Forward)
	Remove(cert *x509.Certificate)

	// TODO maybe hostports?
	Active(ctx context.Context, f func(addrs map[netip.AddrPort]*x509.Certificate) error) error
}

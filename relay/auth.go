package relay

import (
	"crypto/x509"

	"github.com/keihaya-com/connet/model"
)

type Authenticator interface {
	Authenticate(certs []*x509.Certificate) *Authentication
	CertificateAuthority() *x509.CertPool
}

type Authentication struct { // interface like control?
	Certificate  *x509.Certificate
	Destinations map[model.Forward]struct{}
	Sources      map[model.Forward]struct{}
}

func (a *Authentication) AllowDestination(fwd model.Forward) bool {
	_, ok := a.Destinations[fwd]
	return ok
}

func (a *Authentication) AllowSource(fwd model.Forward) bool {
	_, ok := a.Sources[fwd]
	return ok
}

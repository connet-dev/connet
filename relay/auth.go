package relay

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/keihaya-com/connet/model"
)

type Authenticator interface {
	TLSConfig(serverName string) ([]tls.Certificate, *x509.CertPool)
	Authenticate(serverName string, clientCerts []*x509.Certificate) Authentication
}

type Authentication interface {
	Forward() model.Forward
	IsDestination() bool
	IsSource() bool
}

package certc

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/blake2s"
)

type Key struct{ string }

func NewKey(cert *x509.Certificate) Key {
	return newKey(blake2s.Sum256(cert.Raw))
}

func NewKeyTLS(cert tls.Certificate) Key {
	return newKey(blake2s.Sum256(cert.Leaf.Raw))
}

func newKey(sk [blake2s.Size]byte) Key {
	return Key{base58.Encode(sk[:])}
}

func (k Key) String() string {
	return k.string
}

func (k Key) IsValid() bool {
	return k.string != ""
}

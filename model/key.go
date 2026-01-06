package model

import (
	"crypto/x509"

	"github.com/connet-dev/connet/pkg/netc"
	"golang.org/x/crypto/blake2s"
)

type Key struct{ string }

func NewKey(cert *x509.Certificate) Key {
	return newKeyRaw(cert.Raw)
}

func newKeyRaw(raw []byte) Key {
	hash := blake2s.Sum256(raw)
	return Key{netc.DNSSECEncoding.EncodeToString(hash[:])}
}

func NewKeyString(s string) Key {
	return Key{s}
}

func (k Key) String() string {
	return k.string
}

func (k Key) IsValid() bool {
	return k.string != ""
}

func (k Key) MarshalText() ([]byte, error) {
	return []byte(k.string), nil
}

func (k *Key) UnmarshalText(b []byte) error {
	k.string = string(b)
	return nil
}

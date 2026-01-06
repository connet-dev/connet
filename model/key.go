package model

import (
	"crypto/x509"

	"github.com/connet-dev/connet/pkg/netc"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/blake2s"
)

type Key struct{ string }

func NewKey(cert *x509.Certificate) Key {
	return NewKeyRaw(cert.Raw)
}

func NewKeyConn(conn *quic.Conn) Key {
	return NewKeyRaw(conn.ConnectionState().TLS.PeerCertificates[0].Raw)
}

func NewKeyRaw(raw []byte) Key {
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

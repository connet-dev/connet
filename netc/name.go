package netc

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"fmt"
	"io"

	"github.com/mr-tron/base58"
)

var DNSSECEncoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

func GenServerName(prefix string) string {
	data := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s-%s", prefix, base58.Encode(data))
}

func GenServerNameTLS(cert tls.Certificate) string {
	return GenServerNameX509(cert.Leaf)
}

func GenServerNameX509(cert *x509.Certificate) string {
	return genServerNameData(cert.SubjectKeyId)
}

func genServerNameData(data []byte) string {
	return fmt.Sprintf("%s.connet.invalid", DNSSECEncoding.EncodeToString(data))
}

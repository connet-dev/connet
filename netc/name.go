package netc

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
)

var DNSSECEncoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

func GenDomainName(suffix string) string {
	data := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s.%s.invalid", DNSSECEncoding.EncodeToString(data), suffix)
}

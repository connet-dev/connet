package netc

import (
	"crypto/rand"
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

func GenServerNameData(data []byte) string {
	return fmt.Sprintf("%s.connet.invalid", DNSSECEncoding.EncodeToString(data))
}

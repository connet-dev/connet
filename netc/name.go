package netc

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/mr-tron/base58"
)

func GenServerName(prefix string) string {
	data := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s-%s", prefix, base58.Encode(data))
}

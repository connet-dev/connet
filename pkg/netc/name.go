package netc

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

var DNSSECEncoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

func IsSubdomain(domain string, realm string) bool {
	return strings.HasSuffix(domain, fmt.Sprintf(".%s.invalid", realm))
}

func GenDomainName(realm string) string {
	return fmt.Sprintf("%s.%s.invalid", GenName(), realm)
}

func GenName() string {
	data := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return DNSSECEncoding.EncodeToString(data)
}

func GenTimestampName() string {
	data := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	nanos := time.Now().UnixNano()
	binary.BigEndian.PutUint64(data, uint64(nanos))
	return DNSSECEncoding.EncodeToString(data)
}

package control

import (
	"encoding/binary"
	"time"

	"github.com/connet-dev/connet/pkg/netc"
)

type ConnID struct{ string }

var ConnIDNil = ConnID{""}

func NewConnID() ConnID {
	return ConnID{netc.GenTimestampName()}
}

func (k ConnID) String() string {
	return k.string
}

func (k ConnID) Time() time.Time {
	data, err := netc.DNSSECEncoding.DecodeString(k.string)
	if err != nil {
		return time.Time{}
	}
	nanos := binary.BigEndian.Uint64(data)
	return time.Unix(0, int64(nanos))
}

func (k ConnID) MarshalText() ([]byte, error) {
	return []byte(k.string), nil
}

func (k *ConnID) UnmarshalText(b []byte) error {
	k.string = string(b)
	return nil
}

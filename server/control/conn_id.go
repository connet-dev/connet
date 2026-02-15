package control

import "github.com/connet-dev/connet/pkg/netc"

type ConnID struct{ string }

var ConnIDNil = ConnID{""}

func NewConnID() ConnID {
	return ConnID{netc.GenName()}
}

func (k ConnID) String() string {
	return k.string
}

func (k ConnID) MarshalText() ([]byte, error) {
	return []byte(k.string), nil
}

func (k *ConnID) UnmarshalText(b []byte) error {
	k.string = string(b)
	return nil
}

package control

import "github.com/connet-dev/connet/netc"

type RelayID struct{ string }

var RelayIDNil = RelayID{""}

func NewRelayID() RelayID {
	return RelayID{netc.GenName()}
}

func (k RelayID) String() string {
	return k.string
}

func (k RelayID) MarshalText() ([]byte, error) {
	return []byte(k.string), nil
}

func (k *RelayID) UnmarshalText(b []byte) error {
	k.string = string(b)
	return nil
}

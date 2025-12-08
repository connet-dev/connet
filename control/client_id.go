package control

import "github.com/connet-dev/connet/netc"

type ClientID struct{ string }

var ClientIDNil = ClientID{""}

func NewClientID() ClientID {
	return ClientID{netc.GenName()}
}

func (k ClientID) MarshalText() ([]byte, error) {
	return []byte(k.string), nil
}

func (k *ClientID) UnmarshalText(b []byte) error {
	k.string = string(b)
	return nil
}

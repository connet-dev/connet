package control

import (
	"crypto/x509"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
)

type relayClientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	Key     certc.Key     `json:"key"`
}

type relayClientValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v relayClientValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *relayClientValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = relayClientValue{cert}
	return nil
}

type relayServerKey struct {
	Forward  model.Forward  `json:"forward"`
	Hostport model.HostPort `json:"hostport"`
}

type relayServerValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v relayServerValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *relayServerValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = relayServerValue{cert}
	return nil
}

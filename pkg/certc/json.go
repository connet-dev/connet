package certc

import (
	"crypto/x509"
	"encoding/json"
)

func MarshalJSONCert(cert *x509.Certificate) ([]byte, error) {
	s := struct {
		Cert []byte `json:"cert"`
	}{
		Cert: cert.Raw,
	}
	return json.Marshal(s)
}

func UnmarshalJSONCert(b []byte) (*x509.Certificate, error) {
	s := struct {
		Cert []byte `json:"cert"`
	}{}

	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}

	return x509.ParseCertificate(s.Cert)
}

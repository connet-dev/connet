package pb

import "github.com/keihaya-com/connet/certc"

func NewCert(cert, parent *certc.Cert) (*Cert, error) {
	parentDer, _, err := parent.EncodeToMemory()
	if err != nil {
		return nil, err
	}
	der, key, err := cert.EncodeToMemory()
	if err != nil {
		return nil, err
	}
	return &Cert{
		Der:  der,
		Pkey: key,
		Cas:  [][]byte{parentDer},
	}, nil
}

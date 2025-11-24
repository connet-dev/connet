package certc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

var SharedSubject = pkix.Name{
	CommonName: "connet",
}

type Cert struct {
	der []byte
	sk  crypto.PrivateKey
}

func NewRootRandom() (*Cert, error) {
	return NewRoot(nil)
}

func NewRoot(sk ed25519.PrivateKey) (*Cert, error) {
	if sk == nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		sk = priv
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(100, 0, 0),

		Subject: SharedSubject,

		BasicConstraintsValid: true,
		IsCA:                  true,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, sk.Public(), sk)
	if err != nil {
		return nil, err
	}
	return &Cert{der, sk}, nil
}

type CertOpts struct {
	Domains []string
	IPs     []net.IP
}

func (opts CertOpts) subject() (pkix.Name, error) {
	if len(opts.Domains) > 0 {
		return pkix.Name{CommonName: opts.Domains[0]}, nil
	} else if len(opts.IPs) > 0 {
		return pkix.Name{CommonName: opts.IPs[0].String()}, nil
	}

	return pkix.Name{}, fmt.Errorf("missing common name")
}

func (c *Cert) NewServer(opts CertOpts) (*Cert, error) {
	parent, err := x509.ParseCertificate(c.der)
	if err != nil {
		return nil, err
	}

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	subject, err := opts.subject()
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(2, 0, 0),

		Issuer:  parent.Subject,
		Subject: subject,

		DNSNames:    opts.Domains,
		IPAddresses: opts.IPs,

		BasicConstraintsValid: false,
		IsCA:                  false,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, pk, c.sk)
	if err != nil {
		return nil, err
	}

	return &Cert{der, sk}, nil
}

func (c *Cert) NewClient() (*Cert, error) {
	parent, err := x509.ParseCertificate(c.der)
	if err != nil {
		return nil, err
	}

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(2, 0, 0),

		Issuer:  parent.Subject,
		Subject: SharedSubject,

		BasicConstraintsValid: false,
		IsCA:                  false,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, pk, c.sk)
	if err != nil {
		return nil, err
	}

	return &Cert{der, sk}, nil
}

func (c *Cert) Cert() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.der)
}

func (c *Cert) Raw() []byte {
	return c.der
}

func (c *Cert) CertPool() (*x509.CertPool, error) {
	cert, err := c.Cert()
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

func (c *Cert) TLSCert() (tls.Certificate, error) {
	cert, err := c.Cert()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{c.der},
		PrivateKey:  c.sk,
		Leaf:        cert,
	}, nil
}

func (c *Cert) EncodeToMemory() ([]byte, []byte, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.der,
	})

	keyData, err := x509.MarshalPKCS8PrivateKey(c.sk)
	if err != nil {
		return nil, nil, fmt.Errorf("mem key marshal: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyData,
	})
	return certPEM, keyPEM, nil
}

func DecodeFromMemory(cert, key []byte) (*Cert, error) {
	certDER, _ := pem.Decode(cert)
	if certDER == nil {
		return nil, fmt.Errorf("cert: no pem block")
	}
	if certDER.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cert type: %s", certDER.Type)
	}

	keyDER, _ := pem.Decode(key)
	if keyDER == nil {
		return nil, fmt.Errorf("cert key: no pem block")
	}
	if keyDER.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("cert key type: %s", keyDER.Type)
	}

	keyValue, err := x509.ParsePKCS8PrivateKey(keyDER.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cert parse key: %w", err)
	}

	return &Cert{der: certDER.Bytes, sk: keyValue}, nil
}

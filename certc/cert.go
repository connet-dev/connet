package certc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

var SharedSubject = pkix.Name{
	Country:      []string{"US"},
	Organization: []string{"Connet"},
}

type Cert struct {
	der []byte
	sk  crypto.PrivateKey
}

type CertOpts struct {
	Domains    []string
	IPs        []net.IP
	PrivateKey crypto.PrivateKey
}

type certType struct{ string }

var (
	intermediateCert = certType{"intermediate"}
	serverCert       = certType{"server"}
	clientCert       = certType{"client"}
)

func NewRoot() (*Cert, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),

		Subject: SharedSubject,

		BasicConstraintsValid: true,
		IsCA:                  true,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}
	return &Cert{der, priv}, nil
}

func (c *Cert) new(typ certType, opts CertOpts) (*Cert, error) {
	parent, err := x509.ParseCertificate(c.der)
	if err != nil {
		return nil, err
	}

	var privateKey crypto.PrivateKey
	switch parent.PublicKeyAlgorithm {
	case x509.RSA:
		if opts.PrivateKey != nil {
			if rsapk := opts.PrivateKey.(*rsa.PrivateKey); rsapk != nil {
				privateKey = rsapk
			} else {
				privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
			}
		} else {
			privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
		}
	case x509.ECDSA:
		if opts.PrivateKey != nil {
			if edpk := opts.PrivateKey.(*ecdsa.PrivateKey); edpk != nil {
				privateKey = edpk
			} else {
				privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			}
		} else {
			privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		}
	case x509.Ed25519:
		if opts.PrivateKey != nil {
			if edpk := opts.PrivateKey.(ed25519.PrivateKey); edpk != nil {
				privateKey = edpk
			} else {
				_, privateKey, err = ed25519.GenerateKey(rand.Reader)
			}
		} else {
			_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		}
	}
	if err != nil {
		return nil, err
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: SharedSubject,

		DNSNames:    opts.Domains,
		IPAddresses: opts.IPs,
	}

	csrData, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrData)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,

		SerialNumber: big.NewInt(time.Now().UnixMicro()),

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),

		Issuer:  parent.Subject,
		Subject: csr.Subject,

		DNSNames:    opts.Domains,
		IPAddresses: opts.IPs,

		BasicConstraintsValid: false,
		IsCA:                  false,
	}

	switch typ {
	case intermediateCert:
		certTemplate.BasicConstraintsValid = true
		certTemplate.IsCA = true

		switch parent.PublicKeyAlgorithm {
		case x509.RSA:
			// TODO
		case x509.ECDSA:
			// TODO
		case x509.Ed25519:
			certTemplate.SubjectKeyId = csr.PublicKey.(ed25519.PublicKey)
		}

		certTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{}
	case serverCert:
		certTemplate.AuthorityKeyId = parent.SubjectKeyId

		certTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case clientCert:
		certTemplate.AuthorityKeyId = parent.SubjectKeyId

		certTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageContentCommitment
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, csr.PublicKey, c.sk)
	if err != nil {
		return nil, err
	}

	return &Cert{der, privateKey}, nil
}

func (c *Cert) NewIntermediate(opts CertOpts) (*Cert, error) {
	return c.new(intermediateCert, opts)
}

func (c *Cert) NewServer(opts CertOpts) (*Cert, error) {
	return c.new(serverCert, opts)
}

func (c *Cert) NewClient(opts CertOpts) (*Cert, error) {
	return c.new(clientCert, opts)
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

func (c *Cert) Encode(certOut io.Writer, keyOut io.Writer) error {
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.der,
	}); err != nil {
		return fmt.Errorf("cert encode: %w", err)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(c.sk)
	if err != nil {
		return fmt.Errorf("key marshal: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyData,
	}); err != nil {
		return fmt.Errorf("key encode: %w", err)
	}

	return nil
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

func SelfSigned(domain string) (tls.Certificate, *x509.CertPool, error) {
	root, err := NewRoot()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert, err := root.NewServer(CertOpts{
		Domains: []string{domain},
	})
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tlsCert, err := cert.TLSCert()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool, err := cert.CertPool()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tlsCert, pool, nil
}

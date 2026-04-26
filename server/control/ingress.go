package control

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/connet-dev/connet/pkg/restr"
)

type Ingress struct {
	ListenAddress *net.UDPAddr
	ListenTLS     *tls.Config
	Restr         restr.IP
}

type IngressBuilder struct {
	ingress Ingress
	err     error
}

func NewIngressBuilder() *IngressBuilder { return &IngressBuilder{} }

func (b *IngressBuilder) WithListenAddress(addrStr string) *IngressBuilder {
	if b.err != nil {
		return b
	}

	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		b.err = fmt.Errorf("resolve udp address: %w", err)
		return b
	}
	return b.WithListenAddressResolved(addr)
}

func (b *IngressBuilder) WithListenAddressResolved(addr *net.UDPAddr) *IngressBuilder {
	if b.err != nil {
		return b
	}
	b.ingress.ListenAddress = addr
	return b
}

func (b *IngressBuilder) WithListenTLS(cfg *tls.Config) *IngressBuilder {
	if b.err != nil {
		return b
	}

	b.ingress.ListenTLS = cfg
	return b
}

func (b *IngressBuilder) WithListenTLSCert(cert tls.Certificate) *IngressBuilder {
	if b.err != nil {
		return b
	}

	return b.WithListenTLS(&tls.Config{Certificates: []tls.Certificate{cert}})
}

func (b *IngressBuilder) WithListenTLSCertFrom(certFile, keyFile string) *IngressBuilder {
	if b.err != nil {
		return b
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		b.err = fmt.Errorf("load certificate: %w", err)
		return b
	}

	return b.WithListenTLSCert(cert)
}

func (b *IngressBuilder) WithRestr(iprestr restr.IP) *IngressBuilder {
	if b.err != nil {
		return b
	}

	b.ingress.Restr = iprestr
	return b
}

func (b *IngressBuilder) WithRestrFrom(allows []string, denies []string) *IngressBuilder {
	if b.err != nil {
		return b
	}

	iprestr, err := restr.ParseIP(allows, denies)
	if err != nil {
		b.err = fmt.Errorf("parse restrictions: %w", err)
		return b
	}
	return b.WithRestr(iprestr)
}

func (b *IngressBuilder) Error() error {
	return b.err
}

func (b *IngressBuilder) Ingress() (Ingress, error) {
	return b.ingress, b.err
}

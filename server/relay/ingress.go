package relay

import (
	"fmt"
	"net"

	"github.com/connet-dev/connet/pkg/proto/pbmodel"
	"github.com/connet-dev/connet/pkg/restr"
)

type Ingress struct {
	ListenAddress      *net.UDPAddr
	AdvertiseAddresses []string
	Restr              restr.IP
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

func (b *IngressBuilder) WithAdvertiseAddress(addr string) *IngressBuilder {
	if b.err != nil {
		return b
	}
	if _, err := pbmodel.ParseHostPort(addr); err != nil {
		b.err = err
		return b
	}
	b.ingress.AdvertiseAddresses = append(b.ingress.AdvertiseAddresses, addr)
	return b
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
	if b.err != nil {
		return b.ingress, b.err
	}

	for i, addr := range b.ingress.AdvertiseAddresses {
		hp, err := pbmodel.ParseHostPort(addr)
		if err != nil {
			return b.ingress, err
		}
		if hp.Host == "" {
			switch {
			case b.ingress.ListenAddress == nil:
				hp.Host = "localhost"
			case len(b.ingress.ListenAddress.IP) == 0:
				hp.Host = "localhost"
			default:
				hp.Host = b.ingress.ListenAddress.IP.String()
			}
		}
		if hp.Port == 0 {
			switch {
			case b.ingress.ListenAddress == nil:
				hp.Port = 19191
			case b.ingress.ListenAddress.Port == 0:
				hp.Port = 19191 // TODO maybe an error, it might be a random port
			default:
				hp.Port = uint32(b.ingress.ListenAddress.Port)
			}
		}

		b.ingress.AdvertiseAddresses[i] = pbmodel.AddressFromPB(hp)
	}

	return b.ingress, b.err
}

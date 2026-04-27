package relay

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/connet-dev/connet/pkg/proto/pbmodel"
	"github.com/connet-dev/connet/pkg/restr"
)

type Ingress struct {
	ListenAddress      *net.UDPAddr
	AdvertiseAddresses []HostPort
	Restr              restr.IP
}

type HostPort struct {
	Host string
	Port uint16
}

type IngressBuilder struct {
	ingress Ingress
	err     error
}

func NewIngressBuilder() *IngressBuilder { return &IngressBuilder{} }

func (b *IngressBuilder) WithListenAddress(addr *net.UDPAddr) *IngressBuilder {
	if b.err != nil {
		return b
	}
	b.ingress.ListenAddress = addr
	return b
}

func (b *IngressBuilder) WithListenAddressFrom(addrStr string) *IngressBuilder {
	if b.err != nil {
		return b
	}

	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		b.err = fmt.Errorf("resolve udp address: %w", err)
		return b
	}
	return b.WithListenAddress(addr)
}

func (b *IngressBuilder) WithAdvertiseAddress(hp HostPort) *IngressBuilder {
	if b.err != nil {
		return b
	}
	b.ingress.AdvertiseAddresses = append(b.ingress.AdvertiseAddresses, hp)
	return b
}

func (b *IngressBuilder) WithAdvertiseAddressFrom(addr string) *IngressBuilder {
	if b.err != nil {
		return b
	}
	hp, err := parseHostPort(addr)
	if err != nil {
		b.err = err
		return b
	}
	return b.WithAdvertiseAddress(hp)
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

	for i, hp := range b.ingress.AdvertiseAddresses {
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
				hp.Port = uint16(b.ingress.ListenAddress.Port)
			}
		}

		b.ingress.AdvertiseAddresses[i] = hp
	}

	return b.ingress, b.err
}

func parseHostPort(addr string) (HostPort, error) {
	if strings.HasPrefix(addr, "[") {
		closeBracket := strings.LastIndex(addr, "]")
		if closeBracket < 0 {
			return HostPort{}, fmt.Errorf("cannot parse hostport, missing ]")
		}
		colonPort := addr[closeBracket+1:]
		if len(colonPort) > 0 {
			if colonPort[0] != ':' {
				return HostPort{}, fmt.Errorf("cannot parse hostport, missing ':'")
			}
			portStr := colonPort[1:]
			if len(portStr) == 0 {
				return HostPort{}, fmt.Errorf("cannot parse hostport, missing port")
			}
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return HostPort{}, fmt.Errorf("cannot parse port: %w", err)
			}
			return HostPort{Host: addr[:closeBracket+1], Port: uint16(port)}, nil
		}
	} else if colonIndex := strings.LastIndex(addr, ":"); colonIndex != -1 {
		portStr := addr[colonIndex+1:]
		if len(portStr) == 0 {
			return HostPort{}, fmt.Errorf("cannot parse hostport, missing port")
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return HostPort{}, fmt.Errorf("cannot parse port: %w", err)
		}
		return HostPort{Host: addr[:colonIndex], Port: uint16(port)}, nil
	}

	return HostPort{Host: addr}, nil
}

func (hp HostPort) pb() *pbmodel.HostPort {
	return &pbmodel.HostPort{Host: hp.Host, Port: uint32(hp.Port)}
}

package relay

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/restr"
)

type Ingress struct {
	Addr      *net.UDPAddr
	Hostports []model.HostPort
	Restr     restr.IP
}

type IngressBuilder struct {
	ingress Ingress
	err     error
}

func NewIngressBuilder() *IngressBuilder { return &IngressBuilder{} }

func (b *IngressBuilder) WithAddr(addr *net.UDPAddr) *IngressBuilder {
	if b.err != nil {
		return b
	}
	b.ingress.Addr = addr
	return b
}

func (b *IngressBuilder) WithAddrFrom(addrStr string) *IngressBuilder {
	if b.err != nil {
		return b
	}

	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		b.err = fmt.Errorf("resolve udp address: %w", err)
		return b
	}
	return b.WithAddr(addr)
}

func (b *IngressBuilder) WithHostports(hps []model.HostPort) *IngressBuilder {
	if b.err != nil {
		return b
	}
	b.ingress.Hostports = hps
	return b
}

func (b *IngressBuilder) WithHostport(hp model.HostPort) *IngressBuilder {
	if b.err != nil {
		return b
	}
	b.ingress.Hostports = append(b.ingress.Hostports, hp)
	return b
}

func (b *IngressBuilder) WithHostportFrom(hostport string) *IngressBuilder {
	if b.err != nil {
		return b
	}

	if strings.HasPrefix(hostport, "[") {
		closeBracket := strings.LastIndex(hostport, "]")
		if closeBracket < 0 {
			b.err = fmt.Errorf("cannot parse hostport, missing ]")
			return b
		}
		colonPort := hostport[closeBracket+1:]
		if len(colonPort) > 0 {
			if colonPort[0] != ':' {
				b.err = fmt.Errorf("cannot parse hostport, missing ':'")
				return b
			}
			portStr := colonPort[1:]
			if len(portStr) == 0 {
				b.err = fmt.Errorf("cannot parse hostport, missing port")
				return b
			}
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				b.err = fmt.Errorf("cannot parse port: %w", err)
				return b
			}
			return b.WithHostport(model.HostPort{Host: hostport[:closeBracket+1], Port: uint16(port)})
		}
	} else if colonIndex := strings.LastIndex(hostport, ":"); colonIndex != -1 {
		portStr := hostport[colonIndex+1:]
		if len(portStr) == 0 {
			b.err = fmt.Errorf("cannot parse hostport, missing port")
			return b
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			b.err = fmt.Errorf("cannot parse port: %w", err)
			return b
		}
		return b.WithHostport(model.HostPort{Host: hostport[:colonIndex], Port: uint16(port)})
	}

	return b.WithHostport(model.HostPort{Host: hostport})
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

	for i, hp := range b.ingress.Hostports {
		if hp.Host == "" {
			switch {
			case b.ingress.Addr == nil:
				hp.Host = "localhost"
			case len(b.ingress.Addr.IP) == 0:
				hp.Host = "localhost"
			default:
				hp.Host = b.ingress.Addr.IP.String()
			}
		}
		if hp.Port == 0 {
			switch {
			case b.ingress.Addr == nil:
				hp.Port = 19191
			case b.ingress.Addr.Port == 0:
				hp.Port = 19191 // TODO maybe an error, it might be a random port
			default:
				hp.Port = uint16(b.ingress.Addr.Port)
			}
		}

		b.ingress.Hostports[i] = hp
	}

	return b.ingress, b.err
}

package relay

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/restr"
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

	lastCol := strings.LastIndex(hostport, ":")
	if lastCol < 0 {
		if bracketIndex := strings.IndexAny(hostport, "[]"); bracketIndex >= 0 {
			b.err = fmt.Errorf("cannot parse hostport, [ and ] are not allowed")
			return b
		}
		// no ':', just a host, lets use that, will try to set the port at the end
		return b.WithHostport(model.HostPort{Host: hostport})
	}
	if lastCol == 0 {
		// starts with ':', must be a ':port', will try to set the host at the end
		port, err := strconv.ParseInt(hostport[lastCol+1:], 10, 16)
		if err != nil {
			b.err = fmt.Errorf("cannot parse port: %w", err)
			return b
		}
		return b.WithHostport(model.HostPort{Port: uint16(port)})
	}

	if hostport[0] == '[' {
		end := strings.Index(hostport, "]")
		if end < 0 {
			b.err = fmt.Errorf("cannot parse hostport, missing ]")
			return b
		}
		switch end + 1 {
		case len(hostport):
			// ipv6 host without a port, will try to set the port at the end
			return b.WithHostport(model.HostPort{Host: hostport})
		case lastCol:
			// ipv6 host followed by a port
			port, err := strconv.ParseInt(hostport[lastCol+1:], 10, 16)
			if err != nil {
				b.err = fmt.Errorf("cannot parse port: %w", err)
				return b
			}
			return b.WithHostport(model.HostPort{Host: hostport[:lastCol], Port: uint16(port)})
		default:
			if lastCol < end {
				// ipv6 without a port, will try to set the port at the end
				return b.WithHostport(model.HostPort{Host: hostport})
			}
			b.err = fmt.Errorf("port doesn't follow ]")
			return b
		}
	}

	host := hostport[:lastCol]
	if bracketIndex := strings.IndexAny(host, "[]"); bracketIndex >= 0 {
		b.err = fmt.Errorf("cannot parse hostport, [ and ] are not allowed")
		return b
	}
	port, err := strconv.ParseInt(hostport[lastCol+1:], 10, 16)
	if err != nil {
		b.err = fmt.Errorf("cannot parse port: %w", err)
		return b
	}
	return b.WithHostport(model.HostPort{Host: host, Port: uint16(port)})
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

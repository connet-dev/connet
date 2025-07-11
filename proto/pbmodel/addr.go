package pbmodel

import (
	"net"
	"net/netip"

	"github.com/connet-dev/connet/netc"
)

func AddrFromNetip(addr netip.Addr) *Addr {
	if addr.Is6() {
		v6 := addr.As16()
		return &Addr{V6: v6[:]}
	}
	v4 := addr.As4()
	return &Addr{V4: v4[:]}
}

func (a *Addr) AsNetip() netip.Addr {
	if len(a.V6) > 0 {
		return netip.AddrFrom16([16]byte(a.V6))
	}
	return netip.AddrFrom4([4]byte(a.V4))
}

func AddrPortFromNet(addr net.Addr) (*AddrPort, error) {
	a, err := netc.AddrPortFromNet(addr)
	if err != nil {
		return nil, err
	}
	return AddrPortFromNetip(a), nil
}

func AddrPortFromNetip(addr netip.AddrPort) *AddrPort {
	return &AddrPort{
		Addr: AddrFromNetip(addr.Addr()),
		Port: uint32(addr.Port()),
	}
}

func (a *AddrPort) AsNetip() netip.AddrPort {
	return netip.AddrPortFrom(a.Addr.AsNetip(), uint16(a.Port))
}

func AsNetips(pb []*AddrPort) []netip.AddrPort {
	s := make([]netip.AddrPort, len(pb))
	for i, pbi := range pb {
		s[i] = pbi.AsNetip()
	}
	return s
}

func AsAddrPorts(addrs []netip.AddrPort) []*AddrPort {
	s := make([]*AddrPort, len(addrs))
	for i, addr := range addrs {
		s[i] = AddrPortFromNetip(addr)
	}
	return s
}

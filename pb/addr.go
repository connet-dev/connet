package pb

import (
	"net"
	"net/netip"
)

func AddrPortFromNet(addr net.Addr) (*AddrPort, error) {
	switch t := addr.(type) {
	case *net.UDPAddr:
		return AddrPortFromNetip(t.AddrPort()), nil
	case *net.TCPAddr:
		return AddrPortFromNetip(t.AddrPort()), nil
	default:
		naddr, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return nil, err
		}
		return AddrPortFromNetip(naddr), nil
	}
}

func AddrPortFromNetip(addr netip.AddrPort) *AddrPort {
	var paddr *Addr
	if addr.Addr().Is6() {
		v6 := addr.Addr().As16()
		paddr = &Addr{V6: v6[:]}
	} else {
		v4 := addr.Addr().As4()
		paddr = &Addr{V4: v4[:]}
	}

	return &AddrPort{
		Addr: paddr,
		Port: uint32(addr.Port()),
	}
}

func (a *Addr) AsNetip() netip.Addr {
	if len(a.V6) > 0 {
		return netip.AddrFrom16([16]byte(a.V6))
	}
	return netip.AddrFrom4([4]byte(a.V4))
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

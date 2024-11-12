package pb

import (
	"net"
	"net/netip"
)

func NewAddrPort(addr net.Addr) (*AddrPort, error) {
	naddr, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return nil, err
	}

	var paddr *Addr
	if naddr.Addr().Is6() {
		v6 := naddr.Addr().As16()
		paddr = &Addr{V6: v6[:]}
	} else {
		v4 := naddr.Addr().As16()
		paddr = &Addr{V4: v4[:]}
	}

	return &AddrPort{
		Addr: paddr,
		Port: uint32(naddr.Port()),
	}, nil
}

func (a *AddrPort) AsNetip() netip.AddrPort {
	var addr netip.Addr
	if len(a.Addr.V6) > 0 {
		addr = netip.AddrFrom16([16]byte(a.Addr.V6))
	} else {
		addr = netip.AddrFrom4([4]byte(a.Addr.V4))
	}
	return netip.AddrPortFrom(addr, uint16(a.Port))
}

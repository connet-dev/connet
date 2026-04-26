package pbmodel

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/connet-dev/connet/pkg/netc"
)

func AddrFromNetip(addr netip.Addr) *Addr {
	if addr.Is6() {
		v6 := addr.As16()
		return &Addr{V6: v6[:]}
	}
	v4 := addr.As4()
	return &Addr{V4: v4[:]}
}

func (a *Addr) AsNetip() (netip.Addr, error) {
	if a == nil {
		return netip.Addr{}, fmt.Errorf("parse addr: nil")
	}
	if len(a.V6) > 0 {
		if len(a.V6) != 16 {
			return netip.Addr{}, fmt.Errorf("parse addr: v6 length is %d, want 16", len(a.V6))
		}
		return netip.AddrFrom16([16]byte(a.V6)), nil
	}
	if len(a.V4) == 0 {
		return netip.Addr{}, fmt.Errorf("parse addr: v4 and v6 both empty")
	}
	if len(a.V4) != 4 {
		return netip.Addr{}, fmt.Errorf("parse addr: v4 length is %d, want 4", len(a.V4))
	}
	return netip.AddrFrom4([4]byte(a.V4)), nil
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

func (a *AddrPort) AsNetip() (netip.AddrPort, error) {
	if a == nil {
		return netip.AddrPort{}, fmt.Errorf("parse addrport: nil")
	}
	if a.Addr == nil {
		return netip.AddrPort{}, fmt.Errorf("parse addrport: missing addr")
	}
	addr, err := a.Addr.AsNetip()
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, uint16(a.Port)), nil
}

func AsNetips(pb []*AddrPort) ([]netip.AddrPort, error) {
	var err error
	s := make([]netip.AddrPort, len(pb))
	for i, pbi := range pb {
		s[i], err = pbi.AsNetip()
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func AsAddrPorts(addrs []netip.AddrPort) []*AddrPort {
	s := make([]*AddrPort, len(addrs))
	for i, addr := range addrs {
		s[i] = AddrPortFromNetip(addr)
	}
	return s
}

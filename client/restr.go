package client

import (
	"net"
	"net/netip"

	"github.com/connet-dev/connet/netc"
)

type IPRestrictions struct {
	Client  netc.IPRestriction
	Forward netc.IPRestriction
}

func (r IPRestrictions) Accept(addr netip.Addr) bool {
	return r.Client.Accept(addr) && r.Forward.Accept(addr)
}

func (r IPRestrictions) AcceptAddr(addr net.Addr) bool {
	switch taddr := addr.(type) {
	case *net.UDPAddr:
		return r.Accept(taddr.AddrPort().Addr())
	case *net.TCPAddr:
		return r.Accept(taddr.AddrPort().Addr())
	default:
		naddr, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return false
		}
		return r.Accept(naddr.Addr())
	}
}

package netc

import (
	"net"
	"net/netip"
)

type IPRestriction struct {
	allow []netip.Prefix
	deny  []netip.Prefix
}

// ParseIPRestriction parses a slice of allows/denys restrictions in CIDR format.
func ParseIPRestriction(allows []string, denys []string) (IPRestriction, error) {
	restr := IPRestriction{
		allow: make([]netip.Prefix, len(allows)),
		deny:  make([]netip.Prefix, len(denys)),
	}

	var err error
	for i, cidr := range allows {
		restr.allow[i], err = netip.ParsePrefix(cidr)
		if err != nil {
			return IPRestriction{}, err
		}
	}
	for i, cidr := range denys {
		restr.deny[i], err = netip.ParsePrefix(cidr)
		if err != nil {
			return IPRestriction{}, err
		}
	}
	return restr, nil
}

// Accept checks an ip address according to Allow and Deny rules.
//
// If the ip matches any of the Deny rules, Accept returns false.
// If the ip matches any of the Allow rules (after checking all Deny rules), Accept returns true.
//
// Finally, if the ip matches no Allow or Deny rules, Accept returns true only if no explicit Allow rules were defined.
func (r IPRestriction) Accept(ip netip.Addr) bool {
	ip = ip.Unmap() // remove any ipv6 prefix for ipv4

	for _, d := range r.deny {
		if d.Contains(ip) {
			return false
		}
	}

	for _, a := range r.allow {
		if a.Contains(ip) {
			return true
		}
	}

	return len(r.allow) == 0
}

func (r IPRestriction) AcceptAddr(addr net.Addr) bool {
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

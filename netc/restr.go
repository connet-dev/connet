package netc

import (
	"net"
	"net/netip"
)

type IPRestriction struct {
	Allow []netip.Prefix
	Deny  []netip.Prefix
}

func ParseIPRestriction(allows []string, denys []string) (IPRestriction, error) {
	restr := IPRestriction{
		Allow: make([]netip.Prefix, len(allows)),
		Deny:  make([]netip.Prefix, len(denys)),
	}

	var err error
	for i, cidr := range allows {
		restr.Allow[i], err = netip.ParsePrefix(cidr)
		if err != nil {
			return IPRestriction{}, err
		}
	}
	for i, cidr := range denys {
		restr.Deny[i], err = netip.ParsePrefix(cidr)
		if err != nil {
			return IPRestriction{}, err
		}
	}
	return restr, nil
}

// Accept checks an ip address according to Allow and Deny rules
// If the ip matches any of the Deny rules, Accept returns false
// If the ip matches any of the Allow rules (after checking all Deny rules), Accept returns true
// Finally, if the ip matches no Allow or Deny rules, Accept returns true only if no explicit Allow rules were defined
func (r IPRestriction) Accept(ip netip.Addr) bool {
	for _, d := range r.Deny {
		if d.Contains(ip) {
			return false
		}
	}

	for _, a := range r.Allow {
		if a.Contains(ip) {
			return true
		}
	}

	return len(r.Allow) == 0
}

func (r IPRestriction) AcceptAddr(addr net.Addr) bool {
	return false
}

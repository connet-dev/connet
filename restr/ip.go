package restr

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/connet-dev/connet/netc"
)

type IP struct {
	Allows []netip.Prefix `json:"allows,omitempty"`
	Denies []netip.Prefix `json:"denies,omitempty"`
}

// ParseIP parses a slice of allows/denys restrictions in CIDR format.
func ParseIP(allowsStr []string, deniesStr []string) (IP, error) {
	allows, err := netc.ParseCIDRs(allowsStr)
	if err != nil {
		return IP{}, fmt.Errorf("parse allow cidrs %v: %w", allowsStr, err)
	}

	denies, err := netc.ParseCIDRs(deniesStr)
	if err != nil {
		return IP{}, fmt.Errorf("parse deny cidrs: %w", err)
	}

	return IP{allows, denies}, nil
}

func (r IP) IsEmpty() bool {
	return len(r.Allows) == 0 && len(r.Denies) == 0
}

func (r IP) IsNotEmpty() bool {
	return !r.IsEmpty()
}

// IsAllowed checks if an IP address is allowed according to Allows and Denies rules.
//
// If the ip matches any of the Denies rules, IsAllowed returns false.
// If the ip matches any of the Allows rules (after checking all Denies rules), IsAllowed returns true.
//
// Finally, if the ip matches no Allows or Denies rules, IsAllowed returns true only if no explicit Allows rules were defined.
func (r IP) IsAllowed(ip netip.Addr) bool {
	ip = ip.Unmap() // remove any ipv6 prefix for ipv4

	for _, d := range r.Denies {
		if d.Contains(ip) {
			return false
		}
	}

	for _, a := range r.Allows {
		if a.Contains(ip) {
			return true
		}
	}

	return len(r.Allows) == 0
}

// IsAllowedAddr extracts the IP address from net.Addr and checks if it is allowed
func (r IP) IsAllowedAddr(addr net.Addr) bool {
	switch taddr := addr.(type) {
	case *net.UDPAddr:
		return r.IsAllowed(taddr.AddrPort().Addr())
	case *net.TCPAddr:
		return r.IsAllowed(taddr.AddrPort().Addr())
	default:
		naddr, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return false
		}
		return r.IsAllowed(naddr.Addr())
	}
}

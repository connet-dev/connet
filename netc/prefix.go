package netc

import (
	"fmt"
	"net/netip"
)

func ParseCIDRs(strs []string) ([]netip.Prefix, error) {
	var err error
	cidrs := make([]netip.Prefix, len(strs))
	for i, str := range strs {
		cidrs[i], err = ParseCIDR(str)
		if err != nil {
			return nil, fmt.Errorf("parse CIDR at %d: %w", i, err)
		}
	}
	return cidrs, nil
}

func ParseCIDR(str string) (netip.Prefix, error) {
	if cidr, err := netip.ParsePrefix(str); err == nil {
		return cidr, nil
	} else if addr, aerr := netip.ParseAddr(str); aerr == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	} else {
		return netip.Prefix{}, fmt.Errorf("parse CIDR %s: %w", str, err)
	}
}

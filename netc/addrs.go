package netc

import (
	"net"
	"net/netip"
	"strings"

	"github.com/klev-dev/kleverr"
)

func LocalAddrs() ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, kleverr.Ret(err)
	}

	var localAddrs []netip.Addr
	for _, iface := range ifaces {
		if iface.Name == "lo" || strings.HasPrefix(iface.Name, "wg") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

	NEXT:
		for _, addr := range addrs {
			var ip net.IP
			switch ipAddr := addr.(type) {
			case *net.IPAddr:
				ip = ipAddr.IP
			case *net.IPNet:
				ip = ipAddr.IP
			default:
				continue NEXT
			}
			if ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				localAddrs = append(localAddrs, netip.AddrFrom4([4]byte(ip4)))
			}
			if ip6 := ip.To16(); ip6 != nil {
				localAddrs = append(localAddrs, netip.AddrFrom16([16]byte(ip6)))
			}
		}
	}

	return localAddrs, nil
}

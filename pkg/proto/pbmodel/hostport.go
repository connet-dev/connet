package pbmodel

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/connet-dev/connet/pkg/iterc"
)

func AddressFromPB(hp *HostPort) string {
	portstr := strconv.Itoa(int(hp.Port))
	return net.JoinHostPort(hp.Host, portstr)
}

func AddressesFromPBs(hps []*HostPort) []string {
	return iterc.MapSlice(hps, AddressFromPB)
}

func ParseHostPort(addr string) (*HostPort, error) {
	if strings.HasPrefix(addr, "[") {
		closeBracket := strings.LastIndex(addr, "]")
		if closeBracket < 0 {
			return nil, fmt.Errorf("cannot parse hostport, missing ]")
		}
		colonPort := addr[closeBracket+1:]
		if len(colonPort) > 0 {
			if colonPort[0] != ':' {
				return nil, fmt.Errorf("cannot parse hostport, missing ':'")
			}
			portStr := colonPort[1:]
			if len(portStr) == 0 {
				return nil, fmt.Errorf("cannot parse hostport, missing port")
			}
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("cannot parse port: %w", err)
			}
			return &HostPort{Host: addr[:closeBracket+1], Port: uint32(port)}, nil
		}
	} else if colonIndex := strings.LastIndex(addr, ":"); colonIndex != -1 {
		portStr := addr[colonIndex+1:]
		if len(portStr) == 0 {
			return nil, fmt.Errorf("cannot parse hostport, missing port")
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("cannot parse port: %w", err)
		}
		return &HostPort{Host: addr[:colonIndex], Port: uint32(port)}, nil
	}

	return &HostPort{Host: addr}, nil
}

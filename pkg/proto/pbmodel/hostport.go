package pbmodel

import (
	"net"
	"strconv"

	"github.com/connet-dev/connet/pkg/iterc"
)

func AddressFromPB(hp *HostPort) string {
	portstr := strconv.Itoa(int(hp.Port))
	return net.JoinHostPort(hp.Host, portstr)
}

func AddressesFromPBs(hps []*HostPort) []string {
	return iterc.MapSlice(hps, AddressFromPB)
}

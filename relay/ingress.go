package relay

import (
	"net"

	"github.com/connet-dev/connet/restr"
)

type Ingress struct {
	Addr  *net.UDPAddr
	Restr restr.IP
}

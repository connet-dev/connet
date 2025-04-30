package relay

import (
	"net"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/restr"
)

type Ingress struct {
	Addr      *net.UDPAddr
	Hostports []model.HostPort
	Restr     restr.IP
}

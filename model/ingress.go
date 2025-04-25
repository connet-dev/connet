package model

import (
	"net"

	"github.com/connet-dev/connet/restr"
)

type IngressConfig struct {
	Addr  *net.UDPAddr
	Restr restr.IP
}

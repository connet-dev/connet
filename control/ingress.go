package control

import (
	"crypto/tls"
	"net"

	"github.com/connet-dev/connet/restr"
)

type Ingress struct {
	Addr  *net.UDPAddr
	TLS   *tls.Config
	Restr restr.IP
}

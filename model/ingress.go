package model

import (
	"crypto/tls"
	"net"

	"github.com/connet-dev/connet/restr"
)

type IngressConfig struct {
	Addr  *net.UDPAddr
	TLS   *tls.Config
	Restr restr.IP
}

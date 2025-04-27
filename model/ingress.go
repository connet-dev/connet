package model

import (
	"crypto/tls"
	"net"

	"github.com/connet-dev/connet/restr"
)

type IngressConfig struct {
	Addr  *net.UDPAddr
	Restr restr.IP
	TLS   *tls.Config
}

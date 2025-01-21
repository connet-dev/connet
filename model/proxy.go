package model

import (
	"io"
	"net"

	"github.com/connet-dev/connet/pbc"
	"github.com/klev-dev/kleverr"
	"github.com/pires/go-proxyproto"
)

type ProxyVersion struct{ string }

var (
	NoVersion = ProxyVersion{}
	V1        = ProxyVersion{"v1"}
	V2        = ProxyVersion{"v2"}
)

func ProxyVersionFromPB(r pbc.ProxyProtoVersion) ProxyVersion {
	switch r {
	case pbc.ProxyProtoVersion_V1:
		return V1
	case pbc.ProxyProtoVersion_V2:
		return V2
	default:
		return NoVersion
	}
}

func ParseProxyVersion(s string) (ProxyVersion, error) {
	switch s {
	case V1.string:
		return V1, nil
	case V2.string:
		return V2, nil
	}
	return NoVersion, kleverr.Newf("unknown proxy proto version: %s", s)
}

func (v ProxyVersion) PB() pbc.ProxyProtoVersion {
	switch v {
	case V1:
		return pbc.ProxyProtoVersion_V1
	case V2:
		return pbc.ProxyProtoVersion_V2
	default:
		return pbc.ProxyProtoVersion_None
	}
}

func (v ProxyVersion) Write(w io.Writer, conn net.Conn) error {
	if v == NoVersion {
		return nil
	}
	version := byte(2)
	if v == V1 {
		version = byte(1)
	}
	pp := proxyproto.HeaderProxyFromAddrs(version, conn.RemoteAddr(), conn.LocalAddr())
	_, err := pp.WriteTo(w)
	return err
}

package model

import (
	"fmt"
	"io"
	"net"

	"github.com/connet-dev/connet/pbc"
	"github.com/pires/go-proxyproto"
)

type ProxyVersion struct{ string }

var (
	ProxyNone = ProxyVersion{"none"}
	ProxyV1   = ProxyVersion{"v1"}
	ProxyV2   = ProxyVersion{"v2"}
)

func ProxyVersionFromPB(r pbc.ProxyProtoVersion) ProxyVersion {
	switch r {
	case pbc.ProxyProtoVersion_V1:
		return ProxyV1
	case pbc.ProxyProtoVersion_V2:
		return ProxyV2
	default:
		return ProxyNone
	}
}

func ParseProxyVersion(s string) (ProxyVersion, error) {
	switch s {
	case ProxyV1.string:
		return ProxyV1, nil
	case ProxyV2.string:
		return ProxyV2, nil
	}
	return ProxyNone, fmt.Errorf("unknown proxy proto version: %s", s)
}

func (v ProxyVersion) PB() pbc.ProxyProtoVersion {
	switch v {
	case ProxyV1:
		return pbc.ProxyProtoVersion_V1
	case ProxyV2:
		return pbc.ProxyProtoVersion_V2
	default:
		return pbc.ProxyProtoVersion_None
	}
}

func (v ProxyVersion) Write(w io.Writer, conn net.Conn) error {
	if v == ProxyNone {
		return nil
	}
	version := byte(2)
	if v == ProxyV1 {
		version = byte(1)
	}
	pp := proxyproto.HeaderProxyFromAddrs(version, conn.RemoteAddr(), conn.LocalAddr())
	_, err := pp.WriteTo(w)
	return err
}

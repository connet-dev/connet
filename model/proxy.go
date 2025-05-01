package model

import (
	"fmt"
	"net"

	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/pires/go-proxyproto"
)

type ProxyVersion struct{ string }

var (
	ProxyNone = ProxyVersion{"none"}
	ProxyV1   = ProxyVersion{"v1"}
	ProxyV2   = ProxyVersion{"v2"}
)

func ProxyVersionFromPB(r pbclient.ProxyProtoVersion) ProxyVersion {
	switch r {
	case pbclient.ProxyProtoVersion_V1:
		return ProxyV1
	case pbclient.ProxyProtoVersion_V2:
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
	return ProxyNone, fmt.Errorf("invalid proxy proto version: %s", s)
}

func (v ProxyVersion) PB() pbclient.ProxyProtoVersion {
	switch v {
	case ProxyV1:
		return pbclient.ProxyProtoVersion_V1
	case ProxyV2:
		return pbclient.ProxyProtoVersion_V2
	default:
		return pbclient.ProxyProtoVersion_ProxyProtoNone
	}
}

func (v ProxyVersion) Wrap(conn net.Conn) net.Conn {
	if v == ProxyNone {
		return conn
	}
	version := byte(2)
	if v == ProxyV1 {
		version = byte(1)
	}
	return &proxyProtoConn{conn, version}
}

type ProxyProtoConn interface {
	WriteProxyHeader(sourceAddr, destAddr net.Addr) error
}

type proxyProtoConn struct {
	net.Conn
	proxyProtoVersion byte
}

var _ ProxyProtoConn = (*proxyProtoConn)(nil)

func (c *proxyProtoConn) WriteProxyHeader(sourceAddr net.Addr, destAddr net.Addr) error {
	pp := proxyproto.HeaderProxyFromAddrs(c.proxyProtoVersion, sourceAddr, destAddr)
	_, err := pp.WriteTo(c.Conn)
	return err
}

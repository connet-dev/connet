package connet

import (
	"fmt"
	"net"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/proto/pbconnect"
)

// DestinationConfig structure represents destination configuration.
type DestinationConfig struct {
	Endpoint         Endpoint
	Route            RouteOption
	Proxy            ProxyVersion
	RelayEncryptions []model.EncryptionScheme
	DialTimeout      time.Duration
}

// NewDestinationConfig creates a destination config for a given name
func NewDestinationConfig(name string) DestinationConfig {
	return DestinationConfig{
		Endpoint:         NewEndpoint(name),
		Route:            RouteAny,
		Proxy:            ProxyNone,
		RelayEncryptions: []model.EncryptionScheme{model.NoEncryption},
	}
}

// WithRoute sets the route option for this configuration.
func (cfg DestinationConfig) WithRoute(route RouteOption) DestinationConfig {
	cfg.Route = route
	return cfg
}

// WithProxy sets the proxy version option for this configuration.
func (cfg DestinationConfig) WithProxy(proxy ProxyVersion) DestinationConfig {
	cfg.Proxy = proxy
	return cfg
}

// WithRelayEncryptions sets the relay encryptions option for this configuration.
func (cfg DestinationConfig) WithRelayEncryptions(schemes ...model.EncryptionScheme) DestinationConfig {
	cfg.RelayEncryptions = schemes
	return cfg
}

// WithDialTimeout sets the dial timeout
func (cfg DestinationConfig) WithDialTimeout(timeout time.Duration) DestinationConfig {
	cfg.DialTimeout = timeout
	return cfg
}

func (cfg DestinationConfig) endpointConfig() endpointConfig {
	return endpointConfig{
		endpoint: cfg.Endpoint,
		role:     RoleDestination,
		route:    cfg.Route,
	}
}

type ProxyVersion struct{ string }

var (
	ProxyNone = ProxyVersion{"none"}
	ProxyV1   = ProxyVersion{"v1"}
	ProxyV2   = ProxyVersion{"v2"}
)

func ProxyVersionFromPB(r pbconnect.ProxyProtoVersion) ProxyVersion {
	switch r {
	case pbconnect.ProxyProtoVersion_V1:
		return ProxyV1
	case pbconnect.ProxyProtoVersion_V2:
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

func (v ProxyVersion) PB() pbconnect.ProxyProtoVersion {
	switch v {
	case ProxyV1:
		return pbconnect.ProxyProtoVersion_V1
	case ProxyV2:
		return pbconnect.ProxyProtoVersion_V2
	default:
		return pbconnect.ProxyProtoVersion_ProxyProtoNone
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

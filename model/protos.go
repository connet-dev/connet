package model

import (
	"github.com/quic-go/quic-go"
)

// ClientControlNextProto describes TLS NextProtos for clients connecting to control servers
type ClientControlNextProto struct{ string }

func (v ClientControlNextProto) String() string {
	return v.string
}

func GetClientControlNextProto(conn *quic.Conn) ClientControlNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []ClientControlNextProto{ClientControlV02} {
		if v.string == proto {
			return v
		}
	}
	return ClientControlUnknown
}

var (
	ClientControlUnknown = ClientControlNextProto{}
	ClientControlV02     = ClientControlNextProto{"connet-client/0.2"} // 0.8.0
)

// ConnectClientNextProto describes TLS NextProtos for clients connecting to other clients
type ConnectClientNextProto struct{ string }

func (v ConnectClientNextProto) String() string {
	return v.string
}

var (
	ConnectClientV01 = ConnectClientNextProto{"connet-peer/0.1"} // 0.7.0
)

// ConnectRelayNextProto describes TLS NextProtos for clients connecting to relays
type ConnectRelayNextProto struct{ string }

func (v ConnectRelayNextProto) String() string {
	return v.string
}

var (
	ConnectRelayV01 = ConnectRelayNextProto{"connet-peer-relay/0.1"} // 0.7.0
)

type RelayControlNextProto struct{ string }

func (v RelayControlNextProto) String() string {
	return v.string
}

func GetRelayControlNextProto(conn *quic.Conn) RelayControlNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []RelayControlNextProto{RelayControlV02} {
		if v.string == proto {
			return v
		}
	}
	return RelayControlUnknown
}

var (
	RelayControlUnknown = RelayControlNextProto{}
	RelayControlV02     = RelayControlNextProto{"connet-relay/0.2"} // 0.8.0
)

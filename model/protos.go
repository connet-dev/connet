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
	for _, v := range []ClientControlNextProto{ClientControlV03, ClientControlV02} {
		if v.string == proto {
			return v
		}
	}
	return ClientControlUnknown
}

var (
	ClientControlUnknown = ClientControlNextProto{}
	ClientControlV02     = ClientControlNextProto{"connet-client/0.2"} // 0.8.0
	ClientControlV03     = ClientControlNextProto{"connet-client/0.3"} // 0.13.0
	// Update GetClientControlNextProto when adding a new one
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

func GetConnectRelayNextProto(conn *quic.Conn) ConnectRelayNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []ConnectRelayNextProto{ConnectRelayV02} {
		if v.string == proto {
			return v
		}
	}
	return ConnectRelayUnknown
}

var (
	ConnectRelayUnknown = ConnectRelayNextProto{}
	ConnectRelayV02     = ConnectRelayNextProto{"connet-peer-relay/0.2"} // 0.13.0
)

// RelayControlNextProto describes TLS NextProtos for relays connecting to control servers
type RelayControlNextProto struct{ string }

func (v RelayControlNextProto) String() string {
	return v.string
}

func GetRelayControlNextProto(conn *quic.Conn) RelayControlNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []RelayControlNextProto{RelayControlV03} {
		if v.string == proto {
			return v
		}
	}
	return RelayControlUnknown
}

var (
	RelayControlUnknown = RelayControlNextProto{}
	RelayControlV03     = RelayControlNextProto{"connet-relay/0.3"} // 0.13.0
	// Update GetRelayControlNextProto when adding a new one
)

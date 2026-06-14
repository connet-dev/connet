package proto

import (
	"github.com/quic-go/quic-go"
)

// PeerControlNextProto describes TLS NextProtos for clients connecting to control servers
type PeerControlNextProto struct{ string }

func (v PeerControlNextProto) String() string {
	return v.string
}

func GetPeerControlNextProto(conn *quic.Conn) PeerControlNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []PeerControlNextProto{PeerControlV04, PeerControlV03} {
		if v.string == proto {
			return v
		}
	}
	return PeerControlUnknown
}

func GetPeerControlWireVersion(conn *quic.Conn) WireVersion {
	if pv := GetPeerControlNextProto(conn); pv == PeerControlV03 {
		return WireVersion1
	}
	return WireVersion2
}

var (
	PeerControlUnknown = PeerControlNextProto{}
	PeerControlV03     = PeerControlNextProto{"connet-client/0.3"}       // 0.13.0
	PeerControlV04     = PeerControlNextProto{"connet-peer-control/0.4"} // 0.16.0
	PeerControlLatest  = PeerControlV04
	// Update GetClientControlNextProto when adding a new one
)

// PeerNextProto describes TLS NextProtos for peers connecting to each other
type PeerNextProto struct{ string }

func (v PeerNextProto) String() string {
	return v.string
}

func GetPeerNextProto(conn *quic.Conn) PeerNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []PeerNextProto{PeerV02, PeerV01} {
		if v.string == proto {
			return v
		}
	}
	return PeerUnknown
}

func GetPeerWireVersion(conn *quic.Conn) WireVersion {
	if pv := GetPeerNextProto(conn); pv == PeerV01 {
		return WireVersion1
	}
	return WireVersion2
}

var (
	PeerUnknown = PeerNextProto{}
	PeerV01     = PeerNextProto{"connet-peer/0.1"} // 0.7.0
	PeerV02     = PeerNextProto{"connet-peer/0.2"} // 0.16.0
	PeerLatest  = PeerV02
)

// PeerRelayNextProto describes TLS NextProtos for peers connecting to relays
type PeerRelayNextProto struct{ string }

func (v PeerRelayNextProto) String() string {
	return v.string
}

func GetPeerRelayNextProto(conn *quic.Conn) PeerRelayNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []PeerRelayNextProto{PeerRelayV03, PeerRelayV02} {
		if v.string == proto {
			return v
		}
	}
	return PeerRelayUnknown
}

func GetPeerRelayWireVersion(conn *quic.Conn) WireVersion {
	if pv := GetPeerRelayNextProto(conn); pv == PeerRelayV02 {
		return WireVersion1
	}
	return WireVersion2
}

var (
	PeerRelayUnknown = PeerRelayNextProto{}
	PeerRelayV02     = PeerRelayNextProto{"connet-peer-relay/0.2"} // 0.13.0
	PeerRelayV03     = PeerRelayNextProto{"connet-peer-relay/0.3"} // 0.16.0
	PeerRelayLatest  = PeerRelayV03
	// Update GetConnectRelayNextProto when adding a new one
)

// RelayControlNextProto describes TLS NextProtos for relays connecting to control servers
type RelayControlNextProto struct{ string }

func (v RelayControlNextProto) String() string {
	return v.string
}

func GetRelayControlNextProto(conn *quic.Conn) RelayControlNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []RelayControlNextProto{RelayControlV04, RelayControlV03} {
		if v.string == proto {
			return v
		}
	}
	return RelayControlUnknown
}

func GetRelayControlWireVersion(conn *quic.Conn) WireVersion {
	if pv := GetRelayControlNextProto(conn); pv == RelayControlV03 {
		return WireVersion1
	}
	return WireVersion2
}

var (
	RelayControlUnknown = RelayControlNextProto{}
	RelayControlV03     = RelayControlNextProto{"connet-relay/0.3"}         // 0.13.0
	RelayControlV04     = RelayControlNextProto{"connet-relay-control/0.4"} // 0.16.0
	RelayControlLatest  = RelayControlV04
	// Update GetRelayControlNextProto when adding a new one
)

package proto

import (
	"github.com/quic-go/quic-go"
)

// ControlNextProto describes TLS NextProtos for clients connecting to control servers
type ControlNextProto struct{ string }

func (v ControlNextProto) String() string {
	return v.string
}

func GetControlNextProto(conn *quic.Conn) ControlNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []ControlNextProto{ControlV04, ControlV03} {
		if v.string == proto {
			return v
		}
	}
	return ControlUnknown
}

func GetControlWireVersion(conn *quic.Conn) WireVersion {
	if pv := GetControlNextProto(conn); pv == ControlV03 {
		return WireVersion1
	}
	return WireVersion2
}

var (
	ControlUnknown = ControlNextProto{}
	ControlV03     = ControlNextProto{"connet-client/0.3"}  // 0.13.0
	ControlV04     = ControlNextProto{"connet-control/0.4"} // 0.16.0
	ControlLatest  = ControlV04
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

// RelayNextProto describes TLS NextProtos for peers connecting to relays
type RelayNextProto struct{ string }

func (v RelayNextProto) String() string {
	return v.string
}

func GetRelayNextProto(conn *quic.Conn) RelayNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []RelayNextProto{RelayV03, RelayV02} {
		if v.string == proto {
			return v
		}
	}
	return RelayUnknown
}

func GetRelayWireVersion(conn *quic.Conn) WireVersion {
	if pv := GetRelayNextProto(conn); pv == RelayV02 {
		return WireVersion1
	}
	return WireVersion2
}

var (
	RelayUnknown = RelayNextProto{}
	RelayV02     = RelayNextProto{"connet-peer-relay/0.2"} // 0.13.0
	RelayV03     = RelayNextProto{"connet-relay/0.3"}      // 0.16.0
	RelayLatest  = RelayV03
	// Update GetConnectRelayNextProto when adding a new one
)

// ControlRelaysNextProto describes TLS NextProtos for relays connecting to control servers
type ControlRelaysNextProto struct{ string }

func (v ControlRelaysNextProto) String() string {
	return v.string
}

func GetControlRelaysNextProto(conn *quic.Conn) ControlRelaysNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range []ControlRelaysNextProto{ControlRelaysV04, ControlRelaysV03} {
		if v.string == proto {
			return v
		}
	}
	return ControlRelaysUnknown
}

func GetControlRelaysWireVersion(conn *quic.Conn) WireVersion {
	if pv := GetControlRelaysNextProto(conn); pv == ControlRelaysV03 {
		return WireVersion1
	}
	return WireVersion2
}

var (
	ControlRelaysUnknown = ControlRelaysNextProto{}
	ControlRelaysV03     = ControlRelaysNextProto{"connet-relay/0.3"}          // 0.13.0
	ControlRelaysV04     = ControlRelaysNextProto{"connet-control-relays/0.4"} // 0.16.0
	ControlRelaysLatest  = ControlRelaysV04
	// Update GetRelayControlNextProto when adding a new one
)

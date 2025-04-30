package model

import (
	"github.com/connet-dev/connet/iterc"
	"github.com/quic-go/quic-go"
)

type ClientToControlProto struct{ string }

func (v ClientToControlProto) String() string {
	return v.string
}

func GetClientToControlProto(conn quic.Connection) ClientToControlProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range ClientToControlProtos {
		if v.string == proto {
			return v
		}
	}
	return CNUnknown
}

var (
	CNUnknown = ClientToControlProto{}
	CNv00     = ClientToControlProto{"connet"}            // before 0.7.0
	CNv01     = ClientToControlProto{"connet-client/0.1"} // 0.7.0
	CNv02     = ClientToControlProto{"connet-client/0.2"} // 0.8.0
)

var ClientToControlProtos = []ClientToControlProto{CNv02, CNv01, CNv00}

var ClientToControlNextProtos = iterc.MapSlice(ClientToControlProtos, ClientToControlProto.String)

type ClientToClientProto struct{ string }

func (v ClientToClientProto) String() string {
	return v.string
}

var (
	CCv00 = ClientToClientProto{"connet-direct"}   // pre 0.7.0
	CCv01 = ClientToClientProto{"connet-peer/0.1"} // 0.7.0
)

var ClientToClientProtos = []ClientToClientProto{CCv00, CCv01}

var ClientToClientNextProtos = iterc.MapSlice(ClientToClientProtos, ClientToClientProto.String)

type ClientToRelayProto struct{ string }

func (v ClientToRelayProto) String() string {
	return v.string
}

var (
	CRv00 = ClientToRelayProto{"connet-relay"}          // pre 0.7.0
	CRv01 = ClientToRelayProto{"connet-peer-relay/0.1"} // 0.7.0
)

var ClientToRelayProtos = []ClientToRelayProto{CRv01, CRv00}

var ClientToRelayNextProtos = iterc.MapSlice(ClientToRelayProtos, ClientToRelayProto.String)

type RelayToControlProto struct{ string }

func (v RelayToControlProto) String() string {
	return v.string
}

func GetRelayToControlProto(conn quic.Connection) RelayToControlProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range RelayToControlProtos {
		if v.string == proto {
			return v
		}
	}
	return RNUnknown
}

var (
	RNUnknown = RelayToControlProto{}
	RNv00     = RelayToControlProto{"connet-relays"}    // pre 0.7.0
	RNv01     = RelayToControlProto{"connet-relay/0.1"} // 0.7.0
	RNv02     = RelayToControlProto{"connet-relay/0.2"} // 0.8.0
)

var RelayToControlProtos = []RelayToControlProto{RNv02, RNv01, RNv00}

var RelayToControlNextProtos = iterc.MapSlice(RelayToControlProtos, RelayToControlProto.String)

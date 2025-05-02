package model

import (
	"github.com/connet-dev/connet/iterc"
	"github.com/quic-go/quic-go"
)

type ClientNextProto struct{ string }

func (v ClientNextProto) String() string {
	return v.string
}

func GetClientNextProto(conn quic.Connection) ClientNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range AllClientNextProtos {
		if v.string == proto {
			return v
		}
	}
	return CNUnknown
}

var (
	CNUnknown = ClientNextProto{}
	CNv00     = ClientNextProto{"connet"}            // before 0.7.0
	CNv01     = ClientNextProto{"connet-client/0.1"} // 0.7.0
	CNv02     = ClientNextProto{"connet-client/0.2"} // 0.8.0
)

var AllClientNextProtos = []ClientNextProto{CNv02, CNv01, CNv00}

var ClientNextProtos = iterc.MapSliceStrings(AllClientNextProtos)

type ConnectDirectNextProto struct{ string }

func (v ConnectDirectNextProto) String() string {
	return v.string
}

var (
	CCv00 = ConnectDirectNextProto{"connet-direct"}   // pre 0.7.0
	CCv01 = ConnectDirectNextProto{"connet-peer/0.1"} // 0.7.0
)

var AllConnectDirectNextProtos = []ConnectDirectNextProto{CCv00, CCv01}

var ConnectDirectNextProtos = iterc.MapSlice(AllConnectDirectNextProtos, ConnectDirectNextProto.String)

type ConnectRelayNextProto struct{ string }

func (v ConnectRelayNextProto) String() string {
	return v.string
}

var (
	CRv00 = ConnectRelayNextProto{"connet-relay"}          // pre 0.7.0
	CRv01 = ConnectRelayNextProto{"connet-peer-relay/0.1"} // 0.7.0
)

var AllConnectRelayNextProtos = []ConnectRelayNextProto{CRv01, CRv00}

var ConnectRelayNextProtos = iterc.MapSlice(AllConnectRelayNextProtos, ConnectRelayNextProto.String)

type RelayNextProto struct{ string }

func (v RelayNextProto) String() string {
	return v.string
}

func GetRelayNextProto(conn quic.Connection) RelayNextProto {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range AllRelayNextProtos {
		if v.string == proto {
			return v
		}
	}
	return RNUnknown
}

var (
	RNUnknown = RelayNextProto{}
	RNv00     = RelayNextProto{"connet-relays"}    // pre 0.7.0
	RNv01     = RelayNextProto{"connet-relay/0.1"} // 0.7.0
	RNv02     = RelayNextProto{"connet-relay/0.2"} // 0.8.0
)

var AllRelayNextProtos = []RelayNextProto{RNv02, RNv01, RNv00}

var RelayNextProtos = iterc.MapSliceStrings(AllRelayNextProtos)

package pbs

import (
	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/pb"
	"github.com/quic-go/quic-go"
)

type ClientToControlProto struct{ string }

func (v ClientToControlProto) String() string {
	return v.string
}

func GetClientToControlProto(conn quic.Connection) (ClientToControlProto, error) {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range ClientToControlProtos {
		if v.string == proto {
			return v, nil
		}
	}
	return ClientToControlProto{}, pb.NewError(pb.Error_AuthenticationUnknownProtocol, "unknown protocol: %s", proto)
}

var (
	Cv00 = ClientToControlProto{"connet"}
	Cv01 = ClientToControlProto{"connet-control/0.1"}
)

var ClientToControlProtos = []ClientToControlProto{Cv01, Cv00}

var ClientToControlNextProtos = iterc.MapSlice(ClientToControlProtos, ClientToControlProto.String)

type RelayToControlProto struct{ string }

func (v RelayToControlProto) String() string {
	return v.string
}

func GetRelayToControlProto(conn quic.Connection) (RelayToControlProto, error) {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range RelayToControlProtos {
		if v.string == proto {
			return v, nil
		}
	}
	return RelayToControlProto{}, pb.NewError(pb.Error_AuthenticationUnknownProtocol, "unknown protocol: %s", proto)
}

var (
	Rv00 = RelayToControlProto{"connet-relays"}
	Rv01 = RelayToControlProto{"connet-relays/0.1"}
)

var RelayToControlProtos = []RelayToControlProto{Rv01, Rv00}

var RelayToControlNextProtos = iterc.MapSlice(RelayToControlProtos, RelayToControlProto.String)

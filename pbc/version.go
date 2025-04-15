package pbc

import "github.com/connet-dev/connet/iterc"

type ClientToClientProto struct{ string }

func (v ClientToClientProto) String() string {
	return v.string
}

var (
	Cv00 = ClientToClientProto{"connet-direct"}
	Cv01 = ClientToClientProto{"connet-connet/0.1"}
)

var ClientToClientProtos = []ClientToClientProto{Cv00, Cv01}

var ClientToClientNextProtos = iterc.MapSlice(ClientToClientProtos, ClientToClientProto.String)

type ClientToRelayProto struct{ string }

func (v ClientToRelayProto) String() string {
	return v.string
}

var (
	Rv00 = ClientToRelayProto{"connet-relay"}
	Rv01 = ClientToRelayProto{"connet-relay/0.1"}
)

var ClientToRelayProtos = []ClientToRelayProto{Rv01, Rv00}

var ClientToRelayNextProtos = iterc.MapSlice(ClientToRelayProtos, ClientToRelayProto.String)

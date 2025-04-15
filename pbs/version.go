package pbs

import (
	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/pb"
	"github.com/quic-go/quic-go"
)

type ClientVersion struct{ string }

func (v ClientVersion) String() string {
	return v.string
}

func ClientVersionFromConn(conn quic.Connection) (ClientVersion, error) {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range ClientVersions {
		if v.string == proto {
			return v, nil
		}
	}
	return ClientVersion{}, pb.NewError(pb.Error_AuthenticationUnknownProtocol, "unknown protocol: %s", proto)
}

var (
	Cv00 = ClientVersion{"connet"}
	Cv01 = ClientVersion{"connet-control/0.1"}
)

var ClientVersions = []ClientVersion{Cv01, Cv00}

var ClientVersionProtos = iterc.MapSlice(ClientVersions, ClientVersion.String)

type RelayVersion struct{ string }

func (v RelayVersion) String() string {
	return v.string
}

func RelayVersionFromConn(conn quic.Connection) (RelayVersion, error) {
	proto := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, v := range RelayVersions {
		if v.string == proto {
			return v, nil
		}
	}
	return RelayVersion{}, pb.NewError(pb.Error_AuthenticationUnknownProtocol, "unknown protocol: %s", proto)
}

var (
	Rv00 = RelayVersion{"connet-relays"}
	Rv01 = RelayVersion{"connet-relays/0.1"}
)

var RelayVersions = []RelayVersion{Rv01, Rv00}

var RelayVersionProtos = iterc.MapSlice(RelayVersions, RelayVersion.String)

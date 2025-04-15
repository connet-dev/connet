package pbs

import (
	"github.com/connet-dev/connet/iterc"
)

type ClientVersion struct{ string }

func (v ClientVersion) String() string {
	return v.string
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

var (
	Rv00 = RelayVersion{"connet-relays"}
	Rv01 = RelayVersion{"connet-relays/0.1"}
)

var RelayVersions = []RelayVersion{Rv01, Rv00}

var RelayVersionProtos = iterc.MapSlice(RelayVersions, RelayVersion.String)

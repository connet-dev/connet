package model

import (
	"github.com/keihaya-com/connet/pb"
	"github.com/klev-dev/kleverr"
)

type Role struct{ string }

var (
	UnknownRole = Role{}
	Destination = Role{"destination"}
	Source      = Role{"source"}
)

func RoleFromPB(r pb.Role) Role {
	switch r {
	case pb.Role_RoleDestination:
		return Destination
	case pb.Role_RoleSource:
		return Source
	default:
		return UnknownRole
	}
}

func (r Role) PB() pb.Role {
	switch r {
	case Destination:
		return pb.Role_RoleDestination
	case Source:
		return pb.Role_RoleSource
	default:
		return pb.Role_RoleUnknown
	}
}

func (r Role) String() string {
	return r.string
}

func (r Role) MarshalText() ([]byte, error) {
	return []byte(r.string), nil
}

func (r *Role) UnmarshalText(b []byte) error {
	switch s := string(b); s {
	case Destination.string:
		*r = Destination
	case Source.string:
		*r = Source
	default:
		return kleverr.Newf("unknown role: %s", s)
	}
	return nil
}

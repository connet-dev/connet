package model

import (
	"fmt"

	"github.com/connet-dev/connet/proto/pbmodel"
)

type Role struct{ string }

var (
	UnknownRole = Role{}
	Destination = Role{"destination"}
	Source      = Role{"source"}
)

func RoleFromPB(r pbmodel.Role) Role {
	switch r {
	case pbmodel.Role_RoleDestination:
		return Destination
	case pbmodel.Role_RoleSource:
		return Source
	default:
		return UnknownRole
	}
}

func ParseRole(s string) (Role, error) {
	switch s {
	case Destination.string:
		return Destination, nil
	case Source.string:
		return Source, nil
	}
	return UnknownRole, fmt.Errorf("invalid role '%s'", s)
}

func (r Role) PB() pbmodel.Role {
	switch r {
	case Destination:
		return pbmodel.Role_RoleDestination
	case Source:
		return pbmodel.Role_RoleSource
	default:
		return pbmodel.Role_RoleUnknown
	}
}

func (r Role) Invert() Role {
	switch r {
	case Destination:
		return Source
	case Source:
		return Destination
	default:
		return UnknownRole
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
		return fmt.Errorf("invalid role '%s'", s)
	}
	return nil
}

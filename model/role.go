package model

import "github.com/klev-dev/kleverr"

type Role struct{ string }

var (
	UnknownRole = Role{}
	Destination = Role{"destination"}
	Source      = Role{"source"}
)

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

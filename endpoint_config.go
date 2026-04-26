package connet

import (
	"fmt"

	"github.com/connet-dev/connet/pkg/proto/pbmodel"
)

type endpointConfig struct {
	endpoint Endpoint
	role     Role
	route    RouteOption
}

type Endpoint struct{ string }

func NewEndpoint(s string) Endpoint {
	return Endpoint{s}
}

func EndpointFromPB(f *pbmodel.Endpoint) Endpoint {
	return Endpoint{f.Name}
}

func (f Endpoint) PB() *pbmodel.Endpoint {
	return &pbmodel.Endpoint{Name: f.string}
}

func (f Endpoint) String() string {
	return f.string
}

func (f Endpoint) MarshalText() ([]byte, error) {
	return []byte(f.string), nil
}

func (f *Endpoint) UnmarshalText(b []byte) error {
	*f = Endpoint{string(b)}
	return nil
}

func EndpointNames(eps []Endpoint) []string {
	strs := make([]string, len(eps))
	for i, ep := range eps {
		strs[i] = ep.string
	}
	return strs
}

type Role struct{ string }

var (
	RoleUnknown     = Role{}
	RoleDestination = Role{"destination"}
	RoleSource      = Role{"source"}
)

func RoleFromPB(r pbmodel.Role) Role {
	switch r {
	case pbmodel.Role_RoleDestination:
		return RoleDestination
	case pbmodel.Role_RoleSource:
		return RoleSource
	default:
		return RoleUnknown
	}
}

func ParseRole(s string) (Role, error) {
	switch s {
	case RoleDestination.string:
		return RoleDestination, nil
	case RoleSource.string:
		return RoleSource, nil
	}
	return RoleUnknown, fmt.Errorf("invalid role '%s'", s)
}

func (r Role) PB() pbmodel.Role {
	switch r {
	case RoleDestination:
		return pbmodel.Role_RoleDestination
	case RoleSource:
		return pbmodel.Role_RoleSource
	default:
		return pbmodel.Role_RoleUnknown
	}
}

func (r Role) Invert() Role {
	switch r {
	case RoleDestination:
		return RoleSource
	case RoleSource:
		return RoleDestination
	default:
		return RoleUnknown
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
	case RoleDestination.string:
		*r = RoleDestination
	case RoleSource.string:
		*r = RoleSource
	default:
		return fmt.Errorf("invalid role '%s'", s)
	}
	return nil
}

type RouteOption struct{ string }

var (
	RouteAny    = RouteOption{"any"}
	RouteDirect = RouteOption{"direct"}
	RouteRelay  = RouteOption{"relay"}
)

func ParseRouteOption(s string) (RouteOption, error) {
	switch s {
	case RouteAny.string:
		return RouteAny, nil
	case RouteDirect.string:
		return RouteDirect, nil
	case RouteRelay.string:
		return RouteRelay, nil
	}
	return RouteOption{}, fmt.Errorf("invalid route option '%s'", s)
}

func (r RouteOption) AllowFrom(from RouteOption) bool {
	switch from {
	case RouteDirect:
		return r.AllowDirect()
	case RouteRelay:
		return r.AllowRelay()
	}
	return false
}

func (r RouteOption) AllowDirect() bool {
	return r == RouteAny || r == RouteDirect
}

func (r RouteOption) AllowRelay() bool {
	return r == RouteAny || r == RouteRelay
}

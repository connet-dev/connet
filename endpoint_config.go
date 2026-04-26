package connet

import (
	"fmt"
	"slices"

	"github.com/connet-dev/connet/pkg/proto/pbconnect"
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

type EncryptionScheme struct{ string }

var (
	NoEncryption    = EncryptionScheme{"none"}
	TLSEncryption   = EncryptionScheme{"tls"}
	DHXCPEncryption = EncryptionScheme{"dhxcp"}
)

func EncryptionFromPB(pb pbconnect.RelayEncryptionScheme) (EncryptionScheme, error) {
	switch pb {
	case pbconnect.RelayEncryptionScheme_EncryptionNone:
		return NoEncryption, nil
	case pbconnect.RelayEncryptionScheme_TLS:
		return TLSEncryption, nil
	case pbconnect.RelayEncryptionScheme_DHX25519_CHACHAPOLY:
		return DHXCPEncryption, nil
	default:
		return EncryptionScheme{}, fmt.Errorf("invalid encryption scheme: %d", pb)
	}
}

func ParseEncryptionScheme(s string) (EncryptionScheme, error) {
	switch s {
	case NoEncryption.string:
		return NoEncryption, nil
	case TLSEncryption.string:
		return TLSEncryption, nil
	case DHXCPEncryption.string:
		return DHXCPEncryption, nil
	default:
		return EncryptionScheme{}, fmt.Errorf("invalid encryption scheme '%s'", s)
	}
}

func (e EncryptionScheme) PB() pbconnect.RelayEncryptionScheme {
	switch e {
	case NoEncryption:
		return pbconnect.RelayEncryptionScheme_EncryptionNone
	case TLSEncryption:
		return pbconnect.RelayEncryptionScheme_TLS
	case DHXCPEncryption:
		return pbconnect.RelayEncryptionScheme_DHX25519_CHACHAPOLY
	default:
		panic(fmt.Sprintf("invalid encryption scheme: %s", e.string))
	}
}

func PBFromEncryptions(schemes []EncryptionScheme) []pbconnect.RelayEncryptionScheme {
	pbs := make([]pbconnect.RelayEncryptionScheme, len(schemes))
	for i, sc := range schemes {
		pbs[i] = sc.PB()
	}
	return pbs
}

func EncryptionsFromPB(pbs []pbconnect.RelayEncryptionScheme) ([]EncryptionScheme, error) {
	schemes := make([]EncryptionScheme, len(pbs))
	var err error
	for i, s := range pbs {
		schemes[i], err = EncryptionFromPB(s)
		if err != nil {
			return nil, err
		}
	}
	return schemes, nil
}

func SelectEncryptionScheme(dst []EncryptionScheme, src []EncryptionScheme) (EncryptionScheme, error) {
	switch {
	case slices.Contains(dst, TLSEncryption) && slices.Contains(src, TLSEncryption):
		return TLSEncryption, nil
	case slices.Contains(dst, DHXCPEncryption) && slices.Contains(src, DHXCPEncryption):
		return DHXCPEncryption, nil
	case slices.Contains(dst, NoEncryption) && slices.Contains(src, NoEncryption):
		return NoEncryption, nil
	default:
		return EncryptionScheme{}, fmt.Errorf("no shared encryption schemes")
	}
}

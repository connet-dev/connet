package model

import (
	"crypto/x509"

	"github.com/keihaya-com/connet/pbs"
	"github.com/klev-dev/kleverr"
)

type Route struct {
	Hostport    string
	Certificate *x509.Certificate
}

func NewRouteFromPB(r *pbs.Route) (Route, error) {
	if len(r.Certificate) == 0 {
		return Route{Hostport: r.Hostport}, nil
	}
	cert, err := x509.ParseCertificate(r.Certificate)
	if err != nil {
		return Route{}, err
	}
	return Route{
		Hostport:    r.Hostport,
		Certificate: cert,
	}, nil
}

func (r Route) PB() *pbs.Route {
	if r.Certificate == nil {
		return &pbs.Route{Hostport: r.Hostport}
	}
	return &pbs.Route{
		Hostport:    r.Hostport,
		Certificate: r.Certificate.Raw,
	}
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
	return RouteOption{}, kleverr.Newf("unknown route option: %s", s)
}

func (r RouteOption) AllowDirect() bool {
	return r == RouteAny || r == RouteDirect
}

func (r RouteOption) AllowRelay() bool {
	return r == RouteAny || r == RouteRelay
}

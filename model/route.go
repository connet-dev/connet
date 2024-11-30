package model

import "github.com/klev-dev/kleverr"

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

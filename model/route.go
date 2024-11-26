package model

import (
	"crypto/x509"

	"github.com/keihaya-com/connet/pbs"
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

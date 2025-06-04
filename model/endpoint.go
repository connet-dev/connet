package model

import (
	"github.com/connet-dev/connet/proto/pbmodel"
)

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

func PBFromEndpoints(eps []Endpoint) []*pbmodel.Endpoint {
	pbs := make([]*pbmodel.Endpoint, len(eps))
	for i, ep := range eps {
		pbs[i] = ep.PB()
	}
	return pbs
}

func (f Endpoint) MarshalText() ([]byte, error) {
	return []byte(f.string), nil
}

func (f *Endpoint) UnmarshalText(b []byte) error {
	*f = Endpoint{string(b)}
	return nil
}

func EndpointNames(eps []Endpoint) []string {
	var strs = make([]string, len(eps))
	for i, ep := range eps {
		strs[i] = ep.string
	}
	return strs
}

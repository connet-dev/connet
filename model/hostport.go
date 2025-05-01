package model

import (
	"fmt"

	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/proto/pbmodel"
)

type HostPort struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

func HostPortFromPB(h *pbmodel.HostPort) HostPort {
	return HostPort{
		Host: h.Host,
		Port: uint16(h.Port),
	}
}

func HostPortFromPBs(hs []*pbmodel.HostPort) []HostPort {
	return iterc.MapSlice(hs, HostPortFromPB)
}

func (h HostPort) PB() *pbmodel.HostPort {
	return &pbmodel.HostPort{
		Host: h.Host,
		Port: uint32(h.Port),
	}
}

func (h HostPort) String() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

package model

import (
	"fmt"

	"github.com/connet-dev/connet/iterc"
	"github.com/connet-dev/connet/pb"
)

type HostPort struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

func HostPortFromPB(h *pb.HostPort) HostPort {
	return HostPort{
		Host: h.Host,
		Port: uint16(h.Port),
	}
}

func HostPortFromPBs(hs []*pb.HostPort) []HostPort {
	return iterc.MapSlice(hs, HostPortFromPB)
}

func (h HostPort) PB() *pb.HostPort {
	return &pb.HostPort{
		Host: h.Host,
		Port: uint32(h.Port),
	}
}

func (h HostPort) String() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

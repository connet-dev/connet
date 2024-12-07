package model

import (
	"fmt"

	"github.com/keihaya-com/connet/pb"
)

type HostPort struct {
	Host string
	Port uint16
}

func NewHostPortFromPB(h *pb.HostPort) HostPort {
	return HostPort{
		Host: h.Host,
		Port: uint16(h.Port),
	}
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

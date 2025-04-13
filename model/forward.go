package model

import (
	"github.com/connet-dev/connet/pb"
)

type Forward struct{ string }

func NewForward(s string) Forward {
	return Forward{s}
}

func ForwardFromPB(f *pb.Forward) Forward {
	return Forward{f.Name}
}

func (f Forward) PB() *pb.Forward {
	return &pb.Forward{Name: f.string}
}

func (f Forward) String() string {
	return f.string
}

func PBFromForwards(fwds []Forward) []*pb.Forward {
	pbs := make([]*pb.Forward, len(fwds))
	for i, fwd := range fwds {
		pbs[i] = fwd.PB()
	}
	return pbs
}

func (f Forward) MarshalText() ([]byte, error) {
	return []byte(f.string), nil
}

func (f *Forward) UnmarshalText(b []byte) error {
	*f = Forward{string(b)}
	return nil
}

func ForwardNames(fwds []Forward) []string {
	var strs = make([]string, len(fwds))
	for i, fwd := range fwds {
		strs[i] = fwd.string
	}
	return strs
}

package model

import "github.com/keihaya-com/connet/pb"

type Forward struct{ string }

func NewForward(s string) Forward {
	return Forward{s}
}

func NewForwardFromPB(f *pb.Forward) Forward {
	return Forward{f.Name}
}

func (f Forward) String() string {
	return f.string
}

func (f Forward) PB() *pb.Forward {
	return &pb.Forward{Name: f.string}
}

func PBFromForwards(fwds []Forward) []*pb.Forward {
	pbs := make([]*pb.Forward, len(fwds))
	for i, fwd := range fwds {
		pbs[i] = fwd.PB()
	}
	return pbs
}

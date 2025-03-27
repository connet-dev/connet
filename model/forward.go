package model

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/connet-dev/connet/pb"
	"github.com/mr-tron/base58"
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

func GenServerName(prefix string) string {
	data := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s-%s", prefix, base58.Encode(data))
}

func (f Forward) MarshalText() ([]byte, error) {
	return []byte(f.string), nil
}

func (f *Forward) UnmarshalText(b []byte) error {
	*f = Forward{string(b)}
	return nil
}

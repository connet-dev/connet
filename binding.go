package connet

import (
	"fmt"

	"github.com/keihaya-com/connet/pb"
)

type Binding struct {
	Realm string
	Name  string
}

func NewBindingPB(b *pb.Binding) Binding {
	return Binding{
		Realm: b.Realm,
		Name:  b.Name,
	}
}

func (b Binding) AsPB() *pb.Binding {
	return &pb.Binding{
		Realm: b.Realm,
		Name:  b.Name,
	}
}

func (b Binding) String() string {
	return fmt.Sprintf("%s.%s", b.Name, b.Realm)
}

func NewBindingsPB(pbs []*pb.Binding) []Binding {
	s := make([]Binding, len(pbs))
	for i, pb := range pbs {
		s[i] = NewBindingPB(pb)
	}
	return s
}

func AsPBBindings(bs []Binding) []*pb.Binding {
	s := make([]*pb.Binding, len(bs))
	for i, b := range bs {
		s[i] = b.AsPB()
	}
	return s
}

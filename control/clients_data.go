package control

import (
	"encoding/json"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pbs"
	"github.com/segmentio/ksuid"
	"google.golang.org/protobuf/proto"
)

type clientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	ID      ksuid.KSUID   `json:"id"` // TODO consider using the server cert key
}

type clientValue struct {
	peer *pbs.ClientPeer
}

func (v clientValue) MarshalJSON() ([]byte, error) { // TODO proper json
	peerBytes, err := proto.Marshal(v.peer)
	if err != nil {
		return nil, err
	}

	s := struct {
		Data []byte `json:"data"`
	}{
		Data: peerBytes,
	}

	return json.Marshal(s)
}

func (v *clientValue) UnmarshalJSON(b []byte) error {
	s := struct {
		Data []byte `json:"data"`
	}{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	peer := &pbs.ClientPeer{}
	if err := proto.Unmarshal(s.Data, peer); err != nil {
		return err
	}

	*v = clientValue{peer}
	return nil
}

type cacheKey struct {
	forward model.Forward
	role    model.Role
}

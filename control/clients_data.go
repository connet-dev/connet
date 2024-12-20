package control

import (
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pbs"
	"github.com/segmentio/ksuid"
)

type clientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	ID      ksuid.KSUID   `json:"id"` // TODO consider using the server cert key
}

type clientValue struct {
	Peer *pbs.ClientPeer `json:"peer"`
}

type cacheKey struct {
	forward model.Forward
	role    model.Role
}

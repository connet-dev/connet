package selfhosted

import (
	"net"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/restr"
	"github.com/klev-dev/kleverr"
)

func NewClientAuthenticator(auths ...ClientAuthentication) control.ClientAuthenticator {
	s := &clientsAuthenticator{map[string]*ClientAuthentication{}}
	for _, auth := range auths {
		s.tokens[auth.Token] = &auth
	}
	return s
}

type clientsAuthenticator struct {
	tokens map[string]*ClientAuthentication
}

func (s *clientsAuthenticator) Authenticate(token string, addr net.Addr) (control.ClientAuthentication, error) {
	if r, ok := s.tokens[token]; ok && r.IPs.IsAllowedAddr(addr) {
		return r, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

type ClientAuthentication struct {
	Token string
	IPs   restr.IP
	Names restr.Name
}

func (a *ClientAuthentication) Validate(fwd model.Forward, _ model.Role) (model.Forward, error) {
	if !a.Names.IsAllowed(fwd.String()) {
		return model.Forward{}, pb.NewError(pb.Error_ForwardNotAllowed, "forward not allowed: %s", fwd)
	}
	return fwd, nil
}

func (a *ClientAuthentication) MarshalBinary() ([]byte, error) {
	return []byte(a.Token), nil
}

package selfhosted

import (
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/restr"
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

func (s *clientsAuthenticator) Authenticate(req control.ClientAuthenticateRequest) (control.ClientAuthentication, error) {
	r, ok := s.tokens[req.Token]
	if !ok {
		return nil, pb.NewError(pb.Error_AuthenticationFailed, "token not found")
	}
	if !r.IPs.IsAllowedAddr(req.Addr) {
		return nil, pb.NewError(pb.Error_AuthenticationFailed, "address not allowed: %s", req.Addr)
	}
	return r, nil
}

type ClientAuthentication struct {
	Token string
	IPs   restr.IP
	Names restr.Name
	Role  model.Role
}

func (a *ClientAuthentication) Validate(fwd model.Forward, role model.Role) (model.Forward, error) {
	if !a.Names.IsAllowed(fwd.String()) {
		return model.Forward{}, pb.NewError(pb.Error_ForwardNotAllowed, "forward not allowed: %s", fwd)
	}
	if a.Role != model.UnknownRole && a.Role != role {
		return model.Forward{}, pb.NewError(pb.Error_RoleNotAllowed, "role not allowed: %s", role)
	}
	return fwd, nil
}

func (a *ClientAuthentication) MarshalBinary() ([]byte, error) {
	return []byte(a.Token), nil
}

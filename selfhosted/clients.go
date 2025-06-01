package selfhosted

import (
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/restr"
)

type ClientAuthentication struct {
	Token string
	IPs   restr.IP
	Names restr.Name
	Role  model.Role
}

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
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "token not found")
	}
	if !r.IPs.IsAllowedAddr(req.Addr) {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "address not allowed: %s", req.Addr)
	}
	return []byte(req.Token), nil
}

func (s *clientsAuthenticator) Validate(auth control.ClientAuthentication, fwd model.Forward, role model.Role) (model.Forward, error) {
	r, ok := s.tokens[string(auth)]
	if !ok {
		return model.Forward{}, pberror.NewError(pberror.Code_AuthenticationFailed, "token not found")
	}
	if !r.Names.IsAllowed(fwd.String()) {
		return model.Forward{}, pberror.NewError(pberror.Code_ForwardNotAllowed, "forward not allowed: %s", fwd)
	}
	if r.Role != model.UnknownRole && r.Role != role {
		return model.Forward{}, pberror.NewError(pberror.Code_RoleNotAllowed, "role not allowed: %s", role)
	}
	return fwd, nil
}

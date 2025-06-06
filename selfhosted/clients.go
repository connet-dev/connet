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

func (s *clientsAuthenticator) Validate(auth control.ClientAuthentication, endpoint model.Endpoint, role model.Role) (model.Endpoint, error) {
	r, ok := s.tokens[string(auth)]
	if !ok {
		return model.Endpoint{}, pberror.NewError(pberror.Code_AuthenticationFailed, "token not found")
	}
	if !r.Names.IsAllowed(endpoint.String()) {
		return model.Endpoint{}, pberror.NewError(pberror.Code_EndpointNotAllowed, "endpoint not allowed: %s", endpoint)
	}
	if r.Role != model.UnknownRole && r.Role != role {
		return model.Endpoint{}, pberror.NewError(pberror.Code_RoleNotAllowed, "role not allowed: %s", role)
	}
	return endpoint, nil
}

package selfhosted

import (
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/restr"
	"github.com/connet-dev/connet/proto/pberror"
	"github.com/connet-dev/connet/server/control"
)

type RelayAuthentication struct {
	Token string
	IPs   restr.IP
}

func NewRelayAuthenticator(auths ...RelayAuthentication) control.RelayAuthenticator {
	s := &relayAuthenticator{map[string]*RelayAuthentication{}}
	for _, auth := range auths {
		s.tokens[auth.Token] = &auth
	}
	return s
}

type relayAuthenticator struct {
	tokens map[string]*RelayAuthentication
}

func (s *relayAuthenticator) Authenticate(req control.RelayAuthenticateRequest) (control.RelayAuthentication, error) {
	r, ok := s.tokens[req.Token]
	if !ok {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "token not found")
	}
	if !r.IPs.IsAllowedAddr(req.Addr) {
		return nil, pberror.NewError(pberror.Code_AuthenticationFailed, "address not allowed: %s", req.Addr)
	}
	return []byte(r.Token), nil
}

func (s *relayAuthenticator) Allow(_ control.RelayAuthentication, _ control.ClientAuthentication, _ model.Endpoint) (bool, error) {
	return true, nil
}

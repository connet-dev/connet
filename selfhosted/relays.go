package selfhosted

import (
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/restr"
)

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
		return nil, pb.NewError(pb.Error_AuthenticationFailed, "token not found")
	}
	if !r.IPs.IsAllowedAddr(req.Addr) {
		return nil, pb.NewError(pb.Error_AuthenticationFailed, "address not allowed: %s", req.Addr)
	}
	return r, nil
}

func (s *relayAuthenticator) Allow(auth control.RelayAuthentication, _ model.Forward) bool {
	return true
}

type RelayAuthentication struct {
	Token string
	IPs   restr.IP
}

func (r *RelayAuthentication) MarshalBinary() ([]byte, error) {
	return []byte(r.Token), nil
}

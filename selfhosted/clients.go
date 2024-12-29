package selfhosted

import (
	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/klev-dev/kleverr"
)

func NewClientAuthenticator(tokens ...string) control.ClientAuthenticator {
	s := &clientsAuthenticator{map[string]struct{}{}}
	for _, t := range tokens {
		s.tokens[t] = struct{}{}
	}
	return s
}

type clientsAuthenticator struct {
	tokens map[string]struct{}
}

func (s *clientsAuthenticator) Authenticate(token string) (control.ClientAuthentication, error) {
	if _, ok := s.tokens[token]; ok {
		return &clientAuthentication{token}, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

type clientAuthentication struct {
	token string
}

func (a *clientAuthentication) Validate(fwd model.Forward, role model.Role) (model.Forward, error) {
	return fwd, nil
}

func (a *clientAuthentication) MarshalBinary() (data []byte, err error) {
	return []byte(a.token), nil
}

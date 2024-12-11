package selfhosted

import (
	"github.com/keihaya-com/connet/control"
	"github.com/keihaya-com/connet/model"
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

func (a *clientAuthentication) ValidateDestination(dst model.Forward) (model.Forward, error) {
	return dst, nil
}

func (a *clientAuthentication) ValidateSource(src model.Forward) (model.Forward, error) {
	return src, nil
}

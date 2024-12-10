package selfhosted

import (
	"github.com/keihaya-com/connet/control"
	"github.com/keihaya-com/connet/model"
	"github.com/klev-dev/kleverr"
)

func NewStaticAuthenticator(tokens ...string) control.Authenticator {
	s := &staticAuthenticator{map[string]struct{}{}}
	for _, t := range tokens {
		s.tokens[t] = struct{}{}
	}
	return s
}

type staticAuthenticator struct {
	tokens map[string]struct{}
}

func (s *staticAuthenticator) Authenticate(token string) (control.Authentication, error) {
	if _, ok := s.tokens[token]; ok {
		return &staticAuthentication{token}, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

type staticAuthentication struct {
	token string
}

func (a *staticAuthentication) AllowDestination(dst model.Forward) (bool, model.Forward) {
	return true, dst
}

func (a *staticAuthentication) AllowSource(src model.Forward) (bool, model.Forward) {
	return true, src
}

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

func (a *staticAuthentication) ValidateDestination(dst model.Forward) (model.Forward, error) {
	return dst, nil
}

func (a *staticAuthentication) ValidateSource(src model.Forward) (model.Forward, error) {
	return src, nil
}

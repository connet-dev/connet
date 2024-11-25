package authc

import "github.com/klev-dev/kleverr"

type Authentication interface {
	AllowDestination(name string) bool
	AllowSource(name string) bool
}

type Authenticator interface {
	Authenticate(token string) (Authentication, error)
}

func NewStatic(tokens ...string) Authenticator {
	s := &staticAuthenticator{map[string]struct{}{}}
	for _, t := range tokens {
		s.tokens[t] = struct{}{}
	}
	return s
}

type staticAuthentication struct {
	token string
}

func (a *staticAuthentication) AllowDestination(name string) bool {
	return true
}

func (a *staticAuthentication) AllowSource(name string) bool {
	return true
}

type staticAuthenticator struct {
	tokens map[string]struct{}
}

func (s *staticAuthenticator) Authenticate(token string) (Authentication, error) {
	if _, ok := s.tokens[token]; ok {
		return &staticAuthentication{token}, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

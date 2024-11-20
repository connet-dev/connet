package authc

import "github.com/klev-dev/kleverr"

type Authentication struct {
	Realms []string
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

type staticAuthenticator struct {
	tokens map[string]struct{}
}

func (s *staticAuthenticator) Authenticate(token string) (Authentication, error) {
	if _, ok := s.tokens[token]; ok {
		return Authentication{[]string{""}}, nil
	}
	return Authentication{}, kleverr.Newf("invalid token: %s", token)
}

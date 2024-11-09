package authc

import "github.com/klev-dev/kleverr"

type Authentication struct {
	Realms    []string
	SelfRealm string
}

type Authenticator interface {
	Realms() []string
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

func (s *staticAuthenticator) Realms() []string {
	return []string{"local"}
}

func (s *staticAuthenticator) Authenticate(token string) (Authentication, error) {
	if _, ok := s.tokens[token]; ok {
		return Authentication{[]string{"local"}, "local"}, nil
	}
	return Authentication{}, kleverr.Newf("invalid token: %s", token)
}

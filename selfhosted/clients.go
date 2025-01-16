package selfhosted

import (
	"net"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/restr"
	"github.com/klev-dev/kleverr"
)

func NewClientAuthenticator(tokens ...string) (control.ClientAuthenticator, error) {
	return NewClientAuthenticatorRestricted(tokens, nil)
}

func NewClientAuthenticatorRestricted(tokens []string, iprestr []restr.IPRestriction) (control.ClientAuthenticator, error) {
	switch {
	case len(iprestr) == 0:
		iprestr = make([]restr.IPRestriction, len(tokens))
	case len(iprestr) != len(tokens):
		return nil, kleverr.Newf("expected equal number of tokens and token restrictions")
	}

	s := &clientsAuthenticator{map[string]restr.IPRestriction{}}
	for i, t := range tokens {
		s.tokens[t] = iprestr[i]
	}
	return s, nil
}

type clientsAuthenticator struct {
	tokens map[string]restr.IPRestriction
}

func (s *clientsAuthenticator) Authenticate(token string, addr net.Addr) (control.ClientAuthentication, error) {
	if r, ok := s.tokens[token]; ok && r.AcceptAddr(addr) {
		return &clientAuthentication{token}, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

type clientAuthentication struct {
	token string
}

func (a *clientAuthentication) Validate(fwd model.Forward, _ model.Role) (model.Forward, error) {
	return fwd, nil
}

func (a *clientAuthentication) MarshalBinary() ([]byte, error) {
	return []byte(a.token), nil
}

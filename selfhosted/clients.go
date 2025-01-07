package selfhosted

import (
	"net"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/klev-dev/kleverr"
)

func NewClientAuthenticator(tokens ...string) (control.ClientAuthenticator, error) {
	return NewClientAuthenticatorRestricted(tokens, nil)
}

func NewClientAuthenticatorRestricted(tokens []string, restr []netc.IPRestriction) (control.ClientAuthenticator, error) {
	switch {
	case len(restr) == 0:
		restr = make([]netc.IPRestriction, len(tokens))
	case len(restr) != len(tokens):
		return nil, kleverr.Newf("expected equal number of tokens and token restrictions")
	}

	s := &clientsAuthenticator{map[string]netc.IPRestriction{}}
	for i, t := range tokens {
		s.tokens[t] = restr[i]
	}
	return s, nil
}

type clientsAuthenticator struct {
	tokens map[string]netc.IPRestriction
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

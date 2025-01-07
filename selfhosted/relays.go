package selfhosted

import (
	"net"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
	"github.com/klev-dev/kleverr"
)

func NewRelayAuthenticator(tokens ...string) (control.RelayAuthenticator, error) {
	return NewRelayAuthenticatorRestricted(tokens, nil)
}

func NewRelayAuthenticatorRestricted(tokens []string, restr []netc.IPRestriction) (control.RelayAuthenticator, error) {
	switch {
	case len(restr) == 0:
		restr = make([]netc.IPRestriction, len(tokens))
	case len(restr) != len(tokens):
		return nil, kleverr.Newf("expected equal number of tokens and token restrictions")
	}

	s := &relayAuthenticator{map[string]netc.IPRestriction{}}
	for i, t := range tokens {
		s.tokens[t] = restr[i]
	}
	return s, nil
}

type relayAuthenticator struct {
	tokens map[string]netc.IPRestriction
}

func (s *relayAuthenticator) Authenticate(token string, addr net.Addr) (control.RelayAuthentication, error) {
	if r, ok := s.tokens[token]; ok && r.AcceptAddr(addr) {
		return &relayAuthentication{token}, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

type relayAuthentication struct {
	token string
}

func (r *relayAuthentication) Allow(_ model.Forward) bool {
	return true
}

func (r *relayAuthentication) MarshalBinary() ([]byte, error) {
	return []byte(r.token), nil
}

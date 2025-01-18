package selfhosted

import (
	"net"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/restr"
	"github.com/klev-dev/kleverr"
)

func NewClientAuthenticator(tokens ...string) (control.ClientAuthenticator, error) {
	return NewClientAuthenticatorRestricted(tokens, nil, nil)
}

func NewClientAuthenticatorRestricted(tokens []string, iprestr []restr.IP, namerestr []restr.Name) (control.ClientAuthenticator, error) {
	switch {
	case len(iprestr) == 0:
		iprestr = make([]restr.IP, len(tokens))
	case len(iprestr) != len(tokens):
		return nil, kleverr.Newf("expected equal number of tokens and token ip restrictions")
	}

	switch {
	case len(namerestr) == 0:
		namerestr = make([]restr.Name, len(tokens))
	case len(namerestr) != len(tokens):
		return nil, kleverr.Newf("expected equal number of tokens and token name restrictions")
	}

	s := &clientsAuthenticator{map[string]*clientAuthentication{}}
	for i, t := range tokens {
		s.tokens[t] = &clientAuthentication{
			token: t,
			ip:    iprestr[i],
			name:  namerestr[i],
		}
	}
	return s, nil
}

type clientsAuthenticator struct {
	tokens map[string]*clientAuthentication
}

func (s *clientsAuthenticator) Authenticate(token string, addr net.Addr) (control.ClientAuthentication, error) {
	if r, ok := s.tokens[token]; ok && r.ip.IsAllowedAddr(addr) {
		return r, nil
	}
	return nil, kleverr.Newf("invalid token: %s", token)
}

type clientAuthentication struct {
	token string
	ip    restr.IP
	name  restr.Name
}

func (a *clientAuthentication) Validate(fwd model.Forward, _ model.Role) (model.Forward, error) {
	if !a.name.IsAllowed(fwd.String()) {
		return model.Forward{}, pb.NewError(pb.Error_ForwardNotAllowed, "forward not allowed: %s", fwd)
	}
	return fwd, nil
}

func (a *clientAuthentication) MarshalBinary() ([]byte, error) {
	return []byte(a.token), nil
}

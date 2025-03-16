package selfhosted

import (
	"net"

	"github.com/connet-dev/connet/control"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pb"
	"github.com/connet-dev/connet/restr"
)

func NewRelayAuthenticator(auths ...RelayAuthentication) control.RelayAuthenticator {
	s := &relayAuthenticator{map[string]*RelayAuthentication{}}
	for _, auth := range auths {
		s.tokens[auth.Token] = &auth
	}
	return s
}

type relayAuthenticator struct {
	tokens map[string]*RelayAuthentication
}

func (s *relayAuthenticator) Authenticate(token string, addr net.Addr) (control.RelayAuthentication, error) {
	r, ok := s.tokens[token]
	if !ok {
		return nil, pb.NewError(pb.Error_AuthenticationFailed, "token not found")
	}
	if !r.IPs.IsAllowedAddr(addr) {
		return nil, pb.NewError(pb.Error_AuthenticationFailed, "address not allowed: %s", addr)
	}
	return r, nil
}

type RelayAuthentication struct {
	Token string
	IPs   restr.IP
}

func (r *RelayAuthentication) Allow(_ model.Forward) bool {
	return true
}

func (r *RelayAuthentication) MarshalBinary() ([]byte, error) {
	return []byte(r.Token), nil
}

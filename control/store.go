package control

import (
	"crypto/x509"
	"encoding/json"
	"path/filepath"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/segmentio/ksuid"
)

type Stores interface {
	Config() (logc.KV[ConfigKey, ConfigValue], error)

	ClientConns() (logc.KV[ClientConnKey, ClientConnValue], error)
	ClientPeers() (logc.KV[ClientPeerKey, ClientPeerValue], error)

	RelayConns() (logc.KV[RelayConnKey, RelayConnValue], error)
	RelayClients() (logc.KV[RelayClientKey, RelayClientValue], error)
	RelayForwards(id ksuid.KSUID) (logc.KV[RelayForwardKey, RelayForwardValue], error)
	RelayServers() (logc.KV[RelayServerKey, RelayServerValue], error)
	RelayServerOffsets() (logc.KV[RelayConnKey, int64], error)
}

func NewFileStores(dir string) Stores {
	return &fileStores{dir}
}

type fileStores struct {
	dir string
}

func (f *fileStores) Config() (logc.KV[ConfigKey, ConfigValue], error) {
	return logc.NewKV[ConfigKey, ConfigValue](filepath.Join(f.dir, "config"))
}

func (f *fileStores) ClientConns() (logc.KV[ClientConnKey, ClientConnValue], error) {
	return logc.NewKV[ClientConnKey, ClientConnValue](filepath.Join(f.dir, "client-conns"))
}

func (f *fileStores) ClientPeers() (logc.KV[ClientPeerKey, ClientPeerValue], error) {
	return logc.NewKV[ClientPeerKey, ClientPeerValue](filepath.Join(f.dir, "client-peers"))
}

func (f *fileStores) RelayConns() (logc.KV[RelayConnKey, RelayConnValue], error) {
	return logc.NewKV[RelayConnKey, RelayConnValue](filepath.Join(f.dir, "relay-conns"))
}

func (f *fileStores) RelayClients() (logc.KV[RelayClientKey, RelayClientValue], error) {
	return logc.NewKV[RelayClientKey, RelayClientValue](filepath.Join(f.dir, "relay-clients"))
}

func (f *fileStores) RelayForwards(id ksuid.KSUID) (logc.KV[RelayForwardKey, RelayForwardValue], error) {
	return logc.NewKV[RelayForwardKey, RelayForwardValue](filepath.Join(f.dir, "relay-forwards", id.String()))
}

func (f *fileStores) RelayServers() (logc.KV[RelayServerKey, RelayServerValue], error) {
	return logc.NewKV[RelayServerKey, RelayServerValue](filepath.Join(f.dir, "relay-servers"))
}

func (f *fileStores) RelayServerOffsets() (logc.KV[RelayConnKey, int64], error) {
	return logc.NewKV[RelayConnKey, int64](filepath.Join(f.dir, "relay-server-offsets"))
}

type ConfigKey string

var (
	configClientStatelessReset ConfigKey = "client-stateless-reset"
	configRelayStatelessReset  ConfigKey = "relay-stateless-reset"
	configServerID             ConfigKey = "server-id"
	configServerClientSecret   ConfigKey = "server-client-secret"
	configServerRelaySecret    ConfigKey = "server-relay-secret"
)

type ConfigValue struct {
	Int64  int64  `json:"int64,omitempty"`
	String string `json:"string,omitempty"`
	Bytes  []byte `json:"bytes,omitempty"`
}

type ClientConnKey struct {
	ID ksuid.KSUID `json:"id"`
}

type ClientConnValue struct {
	Authentication ClientAuthentication `json:"authentication"`
	Addr           string               `json:"addr"`
}

type ClientPeerKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	ID      ksuid.KSUID   `json:"id"` // TODO consider using the server cert key
}

type ClientPeerValue struct {
	Peer *pbclient.Peer `json:"peer"`
}

type cacheKey struct {
	forward model.Forward
	role    model.Role
}

type RelayConnKey struct {
	ID ksuid.KSUID `json:"id"`
}

type RelayConnValue struct {
	Authentication RelayAuthentication `json:"authentication"`
	Hostport       model.HostPort      `json:"hostport"`
	Hostports      []model.HostPort    `json:"hostports"`
}

type RelayClientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	Key     model.Key     `json:"key"`
}

type RelayClientValue struct {
	Cert           *x509.Certificate    `json:"cert"`
	Authentication ClientAuthentication `json:"authentication"`
}

func (v RelayClientValue) MarshalJSON() ([]byte, error) {
	s := struct {
		Cert           []byte `json:"cert"`
		Authentication []byte `json:"authentication"`
	}{
		Cert:           v.Cert.Raw,
		Authentication: v.Authentication,
	}
	return json.Marshal(s)
}

func (v *RelayClientValue) UnmarshalJSON(b []byte) error {
	s := struct {
		Cert           []byte `json:"cert"`
		Authentication []byte `json:"authentication"`
	}{}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(s.Cert)
	if err != nil {
		return err
	}

	*v = RelayClientValue{cert, s.Authentication}
	return nil
}

type RelayForwardKey struct {
	Forward model.Forward `json:"forward"`
}

type RelayForwardValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v RelayForwardValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *RelayForwardValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = RelayForwardValue{cert}
	return nil
}

type RelayServerKey struct {
	Forward model.Forward `json:"forward"`
	RelayID ksuid.KSUID   `json:"relay_id"`
}

type RelayServerValue struct {
	Hostport  model.HostPort    `json:"hostport"`
	Hostports []model.HostPort  `json:"hostports"`
	Cert      *x509.Certificate `json:"cert"`
}

func (v RelayServerValue) MarshalJSON() ([]byte, error) {
	s := struct {
		Hostport  model.HostPort   `json:"hostport"`
		Hostports []model.HostPort `json:"hostports"`
		Cert      []byte           `json:"cert"`
	}{
		Hostport:  v.Hostport,
		Hostports: v.Hostports,
		Cert:      v.Cert.Raw,
	}
	return json.Marshal(s)
}

func (v *RelayServerValue) UnmarshalJSON(b []byte) error {
	s := struct {
		Hostport  model.HostPort   `json:"hostport"`
		Hostports []model.HostPort `json:"hostports"`
		Cert      []byte           `json:"cert"`
	}{}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(s.Cert)
	if err != nil {
		return err
	}

	*v = RelayServerValue{Hostport: s.Hostport, Hostports: s.Hostports, Cert: cert}
	return nil
}

type relayCacheValue struct {
	Hostports []model.HostPort
	Cert      *x509.Certificate
}

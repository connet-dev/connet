package control

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
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
	RelayEndpoints(id ksuid.KSUID) (logc.KV[RelayEndpointKey, RelayEndpointValue], error)
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

func (f *fileStores) RelayEndpoints(id ksuid.KSUID) (logc.KV[RelayEndpointKey, RelayEndpointValue], error) {
	dir := filepath.Join(f.dir, "relay-forwards", id.String())
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return logc.NewKV[RelayEndpointKey, RelayEndpointValue](filepath.Join(f.dir, "relay-endpoints", id.String()))
	}
	return logc.NewKV[RelayEndpointKey, RelayEndpointValue](dir)
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
	Endpoint model.Endpoint `json:"endpoint"`
	Role     model.Role     `json:"role"`
	ID       ksuid.KSUID    `json:"id"` // TODO consider using the server cert key
}

// TODO remove in 0.10.0
func (v *ClientPeerKey) UnmarshalJSON(b []byte) error {
	s := struct {
		Forward  model.Endpoint `json:"forward"`
		Endpoint model.Endpoint `json:"endpoint"`
		Role     model.Role     `json:"role"`
		ID       ksuid.KSUID    `json:"id"`
	}{}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v.Endpoint = s.Endpoint
	v.Role = s.Role
	v.ID = s.ID
	if v.Endpoint.String() == "" && s.Forward.String() != "" {
		v.Endpoint = s.Forward
	}

	return nil
}

type ClientPeerValue struct {
	Peer *pbclient.Peer `json:"peer"`
}

type cacheKey struct {
	endpoint model.Endpoint
	role     model.Role
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
	Endpoint model.Endpoint `json:"endpoint"`
	Role     model.Role     `json:"role"`
	Key      model.Key      `json:"key"`
}

// TODO remove in 0.10.0
func (v *RelayClientKey) UnmarshalJSON(b []byte) error {
	s := struct {
		Forward  model.Endpoint `json:"forward"`
		Endpoint model.Endpoint `json:"endpoint"`
		Role     model.Role     `json:"role"`
		Key      model.Key      `json:"key"`
	}{}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v.Endpoint = s.Endpoint
	v.Role = s.Role
	v.Key = s.Key
	if v.Endpoint.String() == "" && s.Forward.String() != "" {
		v.Endpoint = s.Forward
	}

	return nil
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

type RelayEndpointKey struct {
	Endpoint model.Endpoint `json:"endpoint"`
}

// TODO remove in 0.10.0
func (v *RelayEndpointKey) UnmarshalJSON(b []byte) error {
	s := struct {
		Forward  model.Endpoint `json:"forward"`
		Endpoint model.Endpoint `json:"endpoint"`
	}{}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v.Endpoint = s.Endpoint
	if v.Endpoint.String() == "" && s.Forward.String() != "" {
		v.Endpoint = s.Forward
	}

	return nil
}

type RelayEndpointValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v RelayEndpointValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *RelayEndpointValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = RelayEndpointValue{cert}
	return nil
}

type RelayServerKey struct {
	Endpoint model.Endpoint `json:"endpoint"`
	RelayID  ksuid.KSUID    `json:"relay_id"`
}

// TODO remove in 0.10.0
func (v *RelayServerKey) UnmarshalJSON(b []byte) error {
	s := struct {
		Forward  model.Endpoint `json:"forward"`
		Endpoint model.Endpoint `json:"endpoint"`
		RelayID  ksuid.KSUID    `json:"relay_id"`
	}{}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v.Endpoint = s.Endpoint
	v.RelayID = s.RelayID
	if v.Endpoint.String() == "" && s.Forward.String() != "" {
		v.Endpoint = s.Forward
	}

	return nil
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

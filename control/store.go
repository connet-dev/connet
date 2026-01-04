package control

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"path/filepath"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto/pbclient"
)

type Stores interface {
	Config() (logc.KV[ConfigKey, ConfigValue], error)

	ClientConns() (logc.KV[ClientConnKey, ClientConnValue], error)
	ClientPeers() (logc.KV[ClientPeerKey, ClientPeerValue], error)

	RelayConns() (logc.KV[RelayConnKey, RelayConnValue], error)
	RelayClients() (logc.KV[RelayClientKey, RelayClientValue], error)
	RelayEndpoints(id RelayID) (logc.KV[RelayEndpointKey, RelayEndpointValue], error)
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

func (f *fileStores) RelayEndpoints(id RelayID) (logc.KV[RelayEndpointKey, RelayEndpointValue], error) {
	return logc.NewKV[RelayEndpointKey, RelayEndpointValue](filepath.Join(f.dir, "relay-endpoints", id.string))
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
	ID ClientID `json:"id"`
}

type ClientConnValue struct {
	Authentication ClientAuthentication `json:"authentication"`
	Addr           string               `json:"addr"`
	Metadata       string               `json:"metadata"`
}

type ClientPeerKey struct {
	Endpoint model.Endpoint `json:"endpoint"`
	Role     model.Role     `json:"role"`
	ID       ClientID       `json:"id"` // TODO consider using the server cert key or peer id
}

type ClientPeerValue struct {
	Peer     *pbclient.Peer `json:"peer"`
	Metadata string         `json:"metadata"`
}

type cacheKey struct {
	endpoint model.Endpoint
	role     model.Role
}

type RelayConnKey struct {
	ID RelayID `json:"id"`
}

type RelayConnValue struct {
	Authentication        RelayAuthentication `json:"authentication"`
	Hostports             []model.HostPort    `json:"hostports"`
	Metadata              string              `json:"metadata"`
	Certificate           *x509.Certificate   `json:"certificate"`
	AuthenticationSignKey ed25519.PrivateKey  `json:"authentication-sign-key"`
}

type jsonRelayConnValue struct {
	Authentication        RelayAuthentication `json:"authentication"`
	Hostports             []model.HostPort    `json:"hostports"`
	Metadata              string              `json:"metadata"`
	Certificate           []byte              `json:"certificate"`
	AuthenticationSignKey []byte              `json:"authentication-sign-key"`
}

func (v RelayConnValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonRelayConnValue{
		Authentication:        v.Authentication,
		Hostports:             v.Hostports,
		Metadata:              v.Metadata,
		Certificate:           v.Certificate.Raw,
		AuthenticationSignKey: v.AuthenticationSignKey,
	})
}

func (v *RelayConnValue) UnmarshalJSON(b []byte) error {
	s := jsonRelayConnValue{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(s.Certificate)
	if err != nil {
		return err
	}

	*v = RelayConnValue{s.Authentication, s.Hostports, s.Metadata, cert, s.AuthenticationSignKey}
	return nil
}

type RelayClientKey struct {
	Endpoint model.Endpoint `json:"endpoint"`
	Role     model.Role     `json:"role"`
	Key      model.Key      `json:"key"`
}

type RelayClientValue struct {
	Cert           *x509.Certificate    `json:"cert"`
	Authentication ClientAuthentication `json:"authentication"`
}

type jsonRelayClientValue struct {
	Cert           []byte `json:"cert"`
	Authentication []byte `json:"authentication"`
}

func (v RelayClientValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonRelayClientValue{
		Cert:           v.Cert.Raw,
		Authentication: v.Authentication,
	})
}

func (v *RelayClientValue) UnmarshalJSON(b []byte) error {
	s := jsonRelayClientValue{}
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
	RelayID  RelayID        `json:"relay_id"`
}

type RelayServerValue struct {
	Hostports []model.HostPort  `json:"hostports"`
	Cert      *x509.Certificate `json:"cert"`
}

type jsonRelayServerValue struct {
	Hostports []model.HostPort `json:"hostports"`
	Cert      []byte           `json:"cert"`
}

func (v RelayServerValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonRelayServerValue{
		Hostports: v.Hostports,
		Cert:      v.Cert.Raw,
	})
}

func (v *RelayServerValue) UnmarshalJSON(b []byte) error {
	s := jsonRelayServerValue{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(s.Cert)
	if err != nil {
		return err
	}

	*v = RelayServerValue{Hostports: s.Hostports, Cert: cert}
	return nil
}

type relayCacheValue struct {
	Hostports []model.HostPort
	Cert      *x509.Certificate
}

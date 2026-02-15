package control

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/logc"
	"github.com/connet-dev/connet/proto/pbclient"
)

type Stores interface {
	Config() (logc.KV[ConfigKey, ConfigValue], error)

	ClientConns() (logc.KV[ClientConnKey, ClientConnValue], error)
	ClientPeers() (logc.KV[ClientPeerKey, ClientPeerValue], error)

	RelayDirects() (logc.KV[RelayConnKey, RelayDirectValue], error)

	RemoveDeprecated() error
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

func (f *fileStores) RelayDirects() (logc.KV[RelayConnKey, RelayDirectValue], error) {
	return logc.NewKV[RelayConnKey, RelayDirectValue](filepath.Join(f.dir, "relay-directs"))
}

func (f *fileStores) RemoveDeprecated() error {
	return errors.Join(
		os.RemoveAll(filepath.Join(f.dir, "relay-conns")),
		os.RemoveAll(filepath.Join(f.dir, "relay-clients")),
		os.RemoveAll(filepath.Join(f.dir, "relay-endpoints")),
		os.RemoveAll(filepath.Join(f.dir, "relay-servers")),
		os.RemoveAll(filepath.Join(f.dir, "relay-server-offsets")),
	)
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
	ID     ClientID `json:"id"`
	ConnID ConnID   `json:"conn_id"`
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
	ConnID   ConnID         `json:"conn_id"`
}

type ClientPeerValue struct {
	Peer     *pbclient.Peer `json:"peer"`
	Metadata string         `json:"metadata"`
}

type RelayConnKey struct {
	ID RelayID `json:"id"`
}

type RelayDirectValue struct {
	Authentication        RelayAuthentication `json:"authentication"`
	Hostports             []model.HostPort    `json:"hostports"`
	Metadata              string              `json:"metadata"`
	Certificate           *x509.Certificate   `json:"certificate"`
	AuthenticationSealKey *[32]byte           `json:"authentication-seal-key"`
}

type jsonRelayDirectValue struct {
	Authentication        RelayAuthentication `json:"authentication"`
	Hostports             []model.HostPort    `json:"hostports"`
	Metadata              string              `json:"metadata"`
	Certificate           []byte              `json:"certificate"`
	AuthenticationSealKey []byte              `json:"authentication-seal-key"`
}

func (v RelayDirectValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonRelayDirectValue{
		Authentication:        v.Authentication,
		Hostports:             v.Hostports,
		Metadata:              v.Metadata,
		Certificate:           v.Certificate.Raw,
		AuthenticationSealKey: v.AuthenticationSealKey[:],
	})
}

func (v *RelayDirectValue) UnmarshalJSON(b []byte) error {
	s := jsonRelayDirectValue{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(s.Certificate)
	if err != nil {
		return err
	}

	var authKey [32]byte
	copy(authKey[:], s.AuthenticationSealKey)
	*v = RelayDirectValue{s.Authentication, s.Hostports, s.Metadata, cert, &authKey}
	return nil
}

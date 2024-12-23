package control

import (
	"crypto/x509"
	"os"
	"path/filepath"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/logc"
	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/pbs"
	"github.com/segmentio/ksuid"
)

type Stores interface {
	Config() (logc.KV[ConfigKey, ConfigValue], error)

	ClientConns() (logc.KV[ClientConnKey, ClientConnValue], error)
	ClientPeers() (logc.KV[ClientPeerKey, ClientPeerValue], error)

	RelayConns() (logc.KV[RelayConnKey, RelayConnValue], error)
	RelayClients() (logc.KV[RelayClientKey, RelayClientValue], error)
	RelayServers() (logc.KV[RelayServerKey, RelayServerValue], error)
	RelayServerOffsets() (logc.KV[RelayConnKey, int64], error)
}

func NewFileStores(dir string) Stores {
	return &fileStores{dir}
}

func NewTmpFileStores() (Stores, error) {
	dir, err := os.MkdirTemp("", "connet-control-")
	if err != nil {
		return nil, err
	}
	return NewFileStores(dir), nil
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

func (f *fileStores) RelayServers() (logc.KV[RelayServerKey, RelayServerValue], error) {
	return logc.NewKV[RelayServerKey, RelayServerValue](filepath.Join(f.dir, "relay-servers"))
}

func (f *fileStores) RelayServerOffsets() (logc.KV[RelayConnKey, int64], error) {
	return logc.NewKV[RelayConnKey, int64](filepath.Join(f.dir, "relay-server-offsets"))
}

type ConfigKey string

var (
	configServerID           ConfigKey = "server-id"
	configServerClientSecret ConfigKey = "server-client-secret"
	configServerRelaySecret  ConfigKey = "server-relay-secret"
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
	Authenication []byte `json:"authentication"`
	Addr          string `json:"addr"`
}

type ClientPeerKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	ID      ksuid.KSUID   `json:"id"` // TODO consider using the server cert key
}

type ClientPeerValue struct {
	Peer *pbs.ClientPeer `json:"peer"`
}

type cacheKey struct {
	forward model.Forward
	role    model.Role
}

type RelayConnKey struct {
	ID ksuid.KSUID `json:"id"`
}

type RelayConnValue struct {
	Authentication []byte         `json:"authentication"`
	Hostport       model.HostPort `json:"hostport"`
}

type RelayClientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	Key     certc.Key     `json:"key"`
}

type RelayClientValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v RelayClientValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *RelayClientValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = RelayClientValue{cert}
	return nil
}

type RelayServerKey struct {
	Forward  model.Forward  `json:"forward"`
	Hostport model.HostPort `json:"hostport"`
}

type RelayServerValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v RelayServerValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *RelayServerValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = RelayServerValue{cert}
	return nil
}

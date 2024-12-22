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

	ClientConns() (logc.KV[ConnKey, ConnValue], error)
	ClientPeers() (logc.KV[PeerKey, PeerValue], error)

	RelayClients() (logc.KV[RelayClientKey, RelayClientValue], error)
	RelayServers() (logc.KV[RelayServerKey, RelayServerValue], error)
	RelayServerOffsets() (logc.KV[model.HostPort, int64], error)
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

func (f *fileStores) ClientConns() (logc.KV[ConnKey, ConnValue], error) {
	return logc.NewKV[ConnKey, ConnValue](filepath.Join(f.dir, "conns"))
}

func (f *fileStores) ClientPeers() (logc.KV[PeerKey, PeerValue], error) {
	return logc.NewKV[PeerKey, PeerValue](filepath.Join(f.dir, "clients"))
}

func (f *fileStores) RelayClients() (logc.KV[RelayClientKey, RelayClientValue], error) {
	return logc.NewKV[RelayClientKey, RelayClientValue](filepath.Join(f.dir, "relay-clients"))
}

func (f *fileStores) RelayServers() (logc.KV[RelayServerKey, RelayServerValue], error) {
	return logc.NewKV[RelayServerKey, RelayServerValue](filepath.Join(f.dir, "relay-servers"))
}

func (f *fileStores) RelayServerOffsets() (logc.KV[model.HostPort, int64], error) {
	return logc.NewKV[model.HostPort, int64](filepath.Join(f.dir, "relay-server-offsets"))
}

type ConfigKey string

var (
	configServerID           ConfigKey = "server-id"
	configServerClientSecret ConfigKey = "server-client-secret"
)

type ConfigValue struct {
	Int64  int64  `json:"int64,omitempty"`
	String string `json:"string,omitempty"`
	Bytes  []byte `json:"bytes,omitempty"`
}

type ConnKey struct {
	ID ksuid.KSUID `json:"id"` // TODO consider using the server cert key
}

type ConnValue struct {
	Token string `json:"token"`
	Addr  string `json:"addr"`
}

type PeerKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	ID      ksuid.KSUID   `json:"id"` // TODO consider using the server cert key
}

type PeerValue struct {
	Peer *pbs.ClientPeer `json:"peer"`
}

type cacheKey struct {
	forward model.Forward
	role    model.Role
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

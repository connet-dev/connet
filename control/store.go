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
	Config() (logc.KV[configKey, configValue], error)

	ClientPeers() (logc.KV[clientKey, clientValue], error)

	RelayClients() (logc.KV[relayClientKey, relayClientValue], error)
	RelayServers() (logc.KV[relayServerKey, relayServerValue], error)
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

func (f *fileStores) Config() (logc.KV[configKey, configValue], error) {
	return logc.NewKV[configKey, configValue](filepath.Join(f.dir, "config"))
}

func (f *fileStores) ClientPeers() (logc.KV[clientKey, clientValue], error) {
	return logc.NewKV[clientKey, clientValue](filepath.Join(f.dir, "clients"))
}

func (f *fileStores) RelayClients() (logc.KV[relayClientKey, relayClientValue], error) {
	return logc.NewKV[relayClientKey, relayClientValue](filepath.Join(f.dir, "relay-clients"))
}

func (f *fileStores) RelayServers() (logc.KV[relayServerKey, relayServerValue], error) {
	return logc.NewKV[relayServerKey, relayServerValue](filepath.Join(f.dir, "relay-servers"))
}

func (f *fileStores) RelayServerOffsets() (logc.KV[model.HostPort, int64], error) {
	return logc.NewKV[model.HostPort, int64](filepath.Join(f.dir, "relay-server-offsets"))
}

type configKey string

var (
	configServerID           configKey = "server-id"
	configServerClientSecret configKey = "server-client-secret"
)

type configValue struct {
	Int64  int64  `json:"int64,omitempty"`
	String string `json:"string,omitempty"`
	Bytes  []byte `json:"bytes,omitempty"`
}

type clientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	ID      ksuid.KSUID   `json:"id"` // TODO consider using the server cert key
}

type clientValue struct {
	Peer *pbs.ClientPeer `json:"peer"`
}

type cacheKey struct {
	forward model.Forward
	role    model.Role
}

type relayClientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	Key     certc.Key     `json:"key"`
}

type relayClientValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v relayClientValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *relayClientValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = relayClientValue{cert}
	return nil
}

type relayServerKey struct {
	Forward  model.Forward  `json:"forward"`
	Hostport model.HostPort `json:"hostport"`
}

type relayServerValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v relayServerValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *relayServerValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = relayServerValue{cert}
	return nil
}

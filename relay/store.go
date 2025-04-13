package relay

import (
	"crypto/x509"
	"encoding/json"
	"path/filepath"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/logc"
	"github.com/connet-dev/connet/model"
)

type Stores interface {
	Config() (logc.KV[ConfigKey, ConfigValue], error)
	Clients() (logc.KV[ClientKey, ClientValue], error)
	Servers() (logc.KV[ServerKey, ServerValue], error)
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

func (f *fileStores) Clients() (logc.KV[ClientKey, ClientValue], error) {
	return logc.NewKV[ClientKey, ClientValue](filepath.Join(f.dir, "clients"))
}

func (f *fileStores) Servers() (logc.KV[ServerKey, ServerValue], error) {
	return logc.NewKV[ServerKey, ServerValue](filepath.Join(f.dir, "servers"))
}

type ConfigKey string

var (
	configStatelessReset      ConfigKey = "stateless-reset"
	configControlID           ConfigKey = "control-id"
	configControlReconnect    ConfigKey = "control-reconnect"
	configClientsStreamOffset ConfigKey = "clients-stream-offset"
	configClientsLogOffset    ConfigKey = "clients-log-offset"
)

type ConfigValue struct {
	Int64  int64  `json:"int64,omitempty"`
	String string `json:"string,omitempty"`
	Bytes  []byte `json:"bytes,omitempty"`
}

type ClientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	Key     model.Key     `json:"key"`
}

type ClientValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v ClientValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *ClientValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = ClientValue{cert}
	return nil
}

type ServerKey struct {
	Forward model.Forward `json:"forward"`
}

type ServerValue struct {
	Name    string                          `json:"name"`
	Cert    *certc.Cert                     `json:"cert"`
	Clients map[serverClientKey]ClientValue `json:"clients"`
}

func (v ServerValue) MarshalJSON() ([]byte, error) {
	cert, key, err := v.Cert.EncodeToMemory()
	if err != nil {
		return nil, err
	}

	s := struct {
		Name    string              `json:"name"`
		Cert    []byte              `json:"cert"`
		CertKey []byte              `json:"cert_key"`
		Clients []serverClientValue `json:"clients"`
	}{
		Name:    v.Name,
		Cert:    cert,
		CertKey: key,
	}

	for k, v := range v.Clients {
		s.Clients = append(s.Clients, serverClientValue{
			Role:  k.Role,
			Value: v,
		})
	}

	return json.Marshal(s)
}

func (v *ServerValue) UnmarshalJSON(b []byte) error {
	s := struct {
		Name    string              `json:"name"`
		Cert    []byte              `json:"cert"`
		CertKey []byte              `json:"cert_key"`
		Clients []serverClientValue `json:"clients"`
	}{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	cert, err := certc.DecodeFromMemory(s.Cert, s.CertKey)
	if err != nil {
		return err
	}

	sv := ServerValue{
		Name:    s.Name,
		Cert:    cert,
		Clients: map[serverClientKey]ClientValue{},
	}

	for _, cl := range s.Clients {
		sv.Clients[serverClientKey{cl.Role, model.NewKey(cl.Value.Cert)}] = cl.Value
	}

	*v = sv
	return nil
}

type serverClientKey struct {
	Role model.Role `json:"role"`
	Key  model.Key  `json:"key"`
}

type serverClientValue struct {
	Role  model.Role  `json:"role"`
	Value ClientValue `json:"value"`
}

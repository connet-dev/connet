package relay

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/logc"
	"github.com/keihaya-com/connet/model"
)

type Stores interface {
	Config(sid string) (logc.KV[configKey, configValue], error)
	Clients(sid string) (logc.KV[clientKey, clientValue], error)
	Servers(sid string) (logc.KV[serverKey, serverValue], error)
}

func NewFileStores(dir string) Stores {
	return &fileStores{dir}
}

func NewTmpFileStores() (Stores, error) {
	dir, err := os.MkdirTemp("", "connet-relay-")
	if err != nil {
		return nil, err
	}
	return NewFileStores(dir), nil
}

type fileStores struct {
	dir string
}

func (f *fileStores) Config(sid string) (logc.KV[configKey, configValue], error) {
	return logc.NewKV[configKey, configValue](filepath.Join(f.dir, sid, "config"))
}

func (f *fileStores) Clients(sid string) (logc.KV[clientKey, clientValue], error) {
	return logc.NewKV[clientKey, clientValue](filepath.Join(f.dir, sid, "clients"))
}

func (f *fileStores) Servers(sid string) (logc.KV[serverKey, serverValue], error) {
	return logc.NewKV[serverKey, serverValue](filepath.Join(f.dir, sid, "servers"))
}

type configKey string

var (
	configClientsStreamOffset configKey = "clients-stream-offset"
	configClientsLogOffset    configKey = "clients-log-offset"
)

type configValue struct {
	Int64 int64 `json:"int64,omitempty"`
}

type clientKey struct {
	Forward model.Forward `json:"forward"`
	Role    model.Role    `json:"role"`
	Key     certc.Key     `json:"key"`
}

type clientValue struct {
	Cert *x509.Certificate `json:"cert"`
}

func (v clientValue) MarshalJSON() ([]byte, error) {
	return certc.MarshalJSONCert(v.Cert)
}

func (v *clientValue) UnmarshalJSON(b []byte) error {
	cert, err := certc.UnmarshalJSONCert(b)
	if err != nil {
		return err
	}

	*v = clientValue{cert}
	return nil
}

type serverKey struct {
	Forward model.Forward `json:"forward"`
}

type serverValue struct {
	Name    string                          `json:"name"`
	Cert    *certc.Cert                     `json:"cert"`
	Clients map[serverClientKey]clientValue `json:"clients"`
}

func (v serverValue) MarshalJSON() ([]byte, error) {
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

func (v *serverValue) UnmarshalJSON(b []byte) error {
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

	sv := serverValue{
		Name:    s.Name,
		Cert:    cert,
		Clients: map[serverClientKey]clientValue{},
	}

	for _, cl := range s.Clients {
		sv.Clients[serverClientKey{cl.Role, certc.NewKey(cl.Value.Cert)}] = cl.Value
	}

	*v = sv
	return nil
}

type serverClientKey struct {
	Role model.Role `json:"role"`
	Key  certc.Key  `json:"key"`
}

type serverClientValue struct {
	Role  model.Role  `json:"role"`
	Value clientValue `json:"value"`
}

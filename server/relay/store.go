package relay

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/connet-dev/connet/pkg/logc"
)

type Stores interface {
	Config() (logc.KV[ConfigKey, ConfigValue], error)

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

func (f *fileStores) RemoveDeprecated() error {
	return errors.Join(
		os.RemoveAll(filepath.Join(f.dir, "clients")),
		os.RemoveAll(filepath.Join(f.dir, "servers")),
	)
}

type ConfigKey string

var (
	configStatelessReset   ConfigKey = "stateless-reset"
	configControlID        ConfigKey = "control-id"
	configControlReconnect ConfigKey = "control-reconnect"
)

type ConfigValue struct {
	Int64  int64  `json:"int64,omitempty"`
	String string `json:"string,omitempty"`
	Bytes  []byte `json:"bytes,omitempty"`
}

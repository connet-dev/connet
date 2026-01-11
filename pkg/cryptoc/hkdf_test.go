package cryptoc

import (
	"crypto/hkdf"
	"encoding/base32"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2s"
)

func TestHKDF1(t *testing.T) {
	ck := make([]byte, blake2s.Size)
	copy(ck, "connet-chaining")

	idata := hkdf1(newhash, ck, []byte("secret"))
	fmt.Println("idata:", base32.StdEncoding.EncodeToString(idata))

	xdata, err := hkdf.Key(newhash, []byte("secret"), ck, "", 32)
	require.NoError(t, err)
	fmt.Println("xdata:", base32.StdEncoding.EncodeToString(xdata))
}

func TestHKDF2(t *testing.T) {
	ck := make([]byte, blake2s.Size)
	copy(ck, "connet-chaining")

	idata1, idata2 := hkdf2(newhash, ck, []byte("secret"))
	fmt.Println("idata1:", base32.StdEncoding.EncodeToString(idata1))
	fmt.Println("idata2:", base32.StdEncoding.EncodeToString(idata2))

	xdata, err := hkdf.Key(newhash, []byte("secret"), ck, "", 64)
	require.NoError(t, err)
	fmt.Println("xdata1:", base32.StdEncoding.EncodeToString(xdata[:32]))
	fmt.Println("xdata2:", base32.StdEncoding.EncodeToString(xdata[32:]))
}

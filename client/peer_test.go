package client

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
)

func TestXX(t *testing.T) {
	srcSecret, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	dstSecret, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	srcF, srcS, err := srcDeriveKeys(srcSecret, dstSecret.PublicKey())
	require.NoError(t, err)
	fmt.Println(base58.Encode(srcF), base58.Encode(srcS))

	dstF, dstS, err := dstDeriveKeys(dstSecret, srcSecret.PublicKey())
	require.NoError(t, err)
	fmt.Println(base58.Encode(dstF), base58.Encode(dstS))
}

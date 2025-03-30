package cryptoc

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveKeys(t *testing.T) {
	srcKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	dstKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	sl, sr, err := DeriveKeys(srcKey, dstKey.PublicKey(), true)
	require.NoError(t, err)
	dl, dr, err := DeriveKeys(dstKey, srcKey.PublicKey(), false)
	require.NoError(t, err)

	require.Equal(t, sl, dl)
	require.Equal(t, sr, dr)
}

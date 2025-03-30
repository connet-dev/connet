package cryptoc

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestStream(t *testing.T) {
	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()

	var client io.ReadWriteCloser = &rwc{clientReader, clientWriter}
	var server io.ReadWriteCloser = &rwc{serverReader, serverWriter}

	var clientAEAD = newAEAD(t)
	var serverAEAD = newAEAD(t)

	var clientStream = NewStream(client, serverAEAD, clientAEAD)
	var serverStream = NewStream(server, clientAEAD, serverAEAD)

	go func() {
		_, err := io.Copy(serverStream, serverStream)
		require.NoError(t, err)
	}()

	t.Run("small", func(t *testing.T) {
		go func() {
			for i := 0; i < 10; i++ {
				var out = []byte(fmt.Sprintf("hello world %d", i))
				_, err := clientStream.Write(out)
				require.NoError(t, err)
			}
		}()

		for i := 0; i < 10; i++ {
			var out = []byte(fmt.Sprintf("hello world %d", i))

			var in = make([]byte, len(out))
			n, err := clientStream.Read(in)
			require.NoError(t, err)
			require.Equal(t, len(out), n)
			require.Equal(t, out, in)
		}
	})

	t.Run("big", func(t *testing.T) {
		var out = make([]byte, 1024*1024)
		_, err := io.ReadFull(rand.Reader, out)
		require.NoError(t, err)

		go func() {
			_, err := clientStream.Write(out)
			require.NoError(t, err)
		}()

		var in = make([]byte, len(out))
		n, err := io.ReadFull(clientStream, in)
		require.NoError(t, err)
		require.Equal(t, len(out), n)
		require.Equal(t, out, in)
	})
}

func newAEAD(t *testing.T) cipher.AEAD {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)
	ccp, err := chacha20poly1305.New(key)
	require.NoError(t, err)
	return ccp
}

type rwc struct {
	reader io.ReadCloser
	writer io.WriteCloser
}

func (r *rwc) Close() error {
	return errors.Join(r.writer.Close(), r.reader.Close())
}

func (r *rwc) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

func (r *rwc) Write(p []byte) (n int, err error) {
	return r.writer.Write(p)
}

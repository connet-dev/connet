package control

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/nacl/secretbox"
)

var errEncryptedDataMissing = errors.New("encrypted data missing")
var errSecretboxOpen = errors.New("secretbox open failed")

type reconnectToken struct {
	secretKey [32]byte
}

func (s *reconnectToken) seal(data []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("generate rand: %w", err)
	}

	return secretbox.Seal(nonce[:], data, &nonce, &s.secretKey), nil
}

func (s *reconnectToken) open(encrypted []byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, errEncryptedDataMissing
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	data, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &s.secretKey)
	if !ok {
		return nil, errSecretboxOpen
	}
	return data, nil
}

func (s *reconnectToken) sealID(id ksuid.KSUID) ([]byte, error) {
	return s.seal(id.Bytes())
}

func (s *reconnectToken) openID(encrypted []byte) (ksuid.KSUID, error) {
	data, err := s.open(encrypted)
	if err != nil {
		return ksuid.Nil, err
	}
	id, err := ksuid.FromBytes(data)
	if err != nil {
		return ksuid.Nil, fmt.Errorf("ksuid decode: %w", err)
	}
	return id, nil
}

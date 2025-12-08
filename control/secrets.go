package control

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

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

func (s *reconnectToken) sealClientID(id ClientID) ([]byte, error) {
	return s.seal([]byte(id.string))
}

func (s *reconnectToken) openClientID(encryptedID []byte) (ClientID, error) {
	data, err := s.open(encryptedID)
	if err != nil {
		return ClientIDNil, err
	}
	// TODO check legnth, if 20 decode?
	return ClientID{string(data)}, nil
}

func (s *reconnectToken) sealRelayID(id RelayID) ([]byte, error) {
	return s.seal([]byte(id.string))
}

func (s *reconnectToken) openRelayID(encryptedID []byte) (RelayID, error) {
	data, err := s.open(encryptedID)
	if err != nil {
		return RelayIDNil, err
	}
	// TODO check legnth, if 20 decode?
	return RelayID{string(data)}, nil
}

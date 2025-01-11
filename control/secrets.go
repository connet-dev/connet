package control

import (
	"crypto/rand"
	"io"

	"github.com/klev-dev/kleverr"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/nacl/secretbox"
)

type reconnectToken struct {
	secretKey [32]byte
}

func (s *reconnectToken) seal(data []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, kleverr.Newf("could not read rand: %w", err)
	}

	return secretbox.Seal(nonce[:], data, &nonce, &s.secretKey), nil
}

func (s *reconnectToken) open(encrypted []byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, kleverr.New("missing encrypted data")
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	data, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &s.secretKey)
	if !ok {
		return nil, kleverr.New("cannot open secretbox")
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
		return ksuid.Nil, kleverr.New("could not decode ksuid")
	}
	return id, nil
}

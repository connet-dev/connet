package control

import (
	"crypto/rand"
	"encoding/binary"
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
	if len(data) == 20 {
		return ClientID{formatBase62(data)}, nil
	}
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
	if len(data) == 20 {
		return RelayID{formatBase62(data)}, nil
	}
	return RelayID{string(data)}, nil
}

const base62Characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const zeroString = "000000000000000000000000000"

func formatBase62(src []byte) string {
	var dst = make([]byte, 27)
	const srcBase = 4294967296
	const dstBase = 62

	// Split src into 5 4-byte words, this is where most of the efficiency comes
	// from because this is a O(N^2) algorithm, and we make N = N / 4 by working
	// on 32 bits at a time.
	parts := [5]uint32{
		binary.BigEndian.Uint32(src[0:4]),
		binary.BigEndian.Uint32(src[4:8]),
		binary.BigEndian.Uint32(src[8:12]),
		binary.BigEndian.Uint32(src[12:16]),
		binary.BigEndian.Uint32(src[16:20]),
	}

	n := len(dst)
	bp := parts[:]
	bq := [5]uint32{}

	for len(bp) != 0 {
		quotient := bq[:0]
		remainder := uint64(0)

		for _, c := range bp {
			value := uint64(c) + uint64(remainder)*srcBase
			digit := value / dstBase
			remainder = value % dstBase

			if len(quotient) != 0 || digit != 0 {
				quotient = append(quotient, uint32(digit))
			}
		}

		// Writes at the end of the destination buffer because we computed the
		// lowest bits first.
		n--
		dst[n] = base62Characters[remainder]
		bp = quotient
	}

	// Add padding at the head of the destination buffer for all bytes that were
	// not set.
	copy(dst[:n], zeroString)
	return string(dst)
}

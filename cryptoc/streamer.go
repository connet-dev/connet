package cryptoc

import (
	"crypto/ecdh"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

type Streamer func(net.Conn) net.Conn

func NewStreamer(selfSecret *ecdh.PrivateKey, peerPublic *ecdh.PublicKey, initiator bool) (Streamer, error) {
	lKey, rKey, err := DeriveKeys(selfSecret, peerPublic, initiator)
	if err != nil {
		return nil, err
	}

	lCipher, err := chacha20poly1305.New(lKey)
	if err != nil {
		return nil, err
	}

	rCipher, err := chacha20poly1305.New(rKey)
	if err != nil {
		return nil, err
	}

	return func(rwc net.Conn) net.Conn {
		if initiator {
			return NewStream(rwc, rCipher, lCipher)
		}
		return NewStream(rwc, lCipher, rCipher)
	}, nil
}

package cryptoc

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"hash"

	"golang.org/x/crypto/blake2s"
)

func DeriveKeys(selfSecret *ecdh.PrivateKey, peerPublic *ecdh.PublicKey, initiator bool) ([]byte, []byte, error) {
	ck, hk := initck()

	if initiator {
		hk = mixHash(hk, selfSecret.PublicKey().Bytes())
		hk = mixHash(hk, peerPublic.Bytes())
	} else {
		hk = mixHash(hk, peerPublic.Bytes())
		hk = mixHash(hk, selfSecret.PublicKey().Bytes())
	}

	dh, err := selfSecret.ECDH(peerPublic)
	if err != nil {
		return nil, nil, err
	}
	ck = hkdf1(newhash, ck, dh)

	hk1, hk2 := hkdf2(newhash, ck, hk)
	return hk1, hk2, nil
}

func DeriveKeys1(selfSecret *ecdh.PrivateKey, peerPublic *ecdh.PublicKey, initiator bool) ([]byte, []byte, error) {
	ck, hk := initck()

	if initiator {
		hk = mixHash(hk, selfSecret.PublicKey().Bytes())
		hk = mixHash(hk, peerPublic.Bytes())
	} else {
		hk = mixHash(hk, peerPublic.Bytes())
		hk = mixHash(hk, selfSecret.PublicKey().Bytes())
	}

	dh, err := selfSecret.ECDH(peerPublic)
	if err != nil {
		return nil, nil, err
	}
	ck, err = hkdf.Key(newhash, dh, ck, "", 32)
	if err != nil {
		return nil, nil, err
	}

	fk, err := hkdf.Key(newhash, hk, ck, "", 64)
	if err != nil {
		return nil, nil, err
	}
	return fk[:32], fk[32:], nil
}

func initck() ([]byte, []byte) {
	ck := make([]byte, blake2s.Size)
	copy(ck, "connet-chaining")

	hk := make([]byte, blake2s.Size)
	copy(hk, "connet-hashing")

	return ck, hk
}

func newhash() hash.Hash {
	h, err := blake2s.New256([]byte("connet-hash"))
	if err != nil {
		panic(err)
	}
	return h
}

func mixHash(oldHash, data []byte) []byte {
	h := newhash()
	h.Write(oldHash)
	h.Write(data)
	return h.Sum(nil)
}

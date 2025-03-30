package cryptoc

import (
	"crypto/hmac"
	"hash"
)

type hasher func() hash.Hash

func hkdf1(h hasher, chainingKey, inputKey []byte) []byte {
	tempMac := hmac.New(h, chainingKey)
	tempMac.Write(inputKey)
	tempKey := tempMac.Sum(nil)

	out1Mac := hmac.New(h, tempKey)
	out1Mac.Write([]byte{0x01})
	return out1Mac.Sum(nil)
}

func hkdf2(h hasher, chainingKey, inputKey []byte) ([]byte, []byte) {
	tempMac := hmac.New(h, chainingKey)
	tempMac.Write(inputKey)
	tempKey := tempMac.Sum(nil)

	out1Mac := hmac.New(h, tempKey)
	out1Mac.Write([]byte{0x01})
	out1 := out1Mac.Sum(nil)

	out2Mac := hmac.New(h, tempKey)
	out2Mac.Write(out1)
	out2Mac.Write([]byte{0x02})
	out2 := out2Mac.Sum(nil)

	return out1, out2
}

func hkdf3(h hasher, chainingKey, inputKey []byte) ([]byte, []byte, []byte) {
	tempMac := hmac.New(h, chainingKey)
	tempMac.Write(inputKey)
	tempKey := tempMac.Sum(nil)

	out1Mac := hmac.New(h, tempKey)
	out1Mac.Write([]byte{0x01})
	out1 := out1Mac.Sum(nil)

	out2Mac := hmac.New(h, tempKey)
	out2Mac.Write(out1)
	out2Mac.Write([]byte{0x02})
	out2 := out2Mac.Sum(nil)

	out3Mac := hmac.New(h, tempKey)
	out3Mac.Write(out2)
	out3Mac.Write([]byte{0x03})
	out3 := out3Mac.Sum(nil)

	return out1, out2, out3
}

var _ = hkdf3

package model

import (
	"fmt"
	"slices"

	"github.com/connet-dev/connet/proto/pbconnect"
)

type EncryptionScheme struct{ string }

var (
	NoEncryption    = EncryptionScheme{"none"}
	TLSEncryption   = EncryptionScheme{"tls"}
	DHXCPEncryption = EncryptionScheme{"dhxcp"}
)

func EncryptionFromPB(pb pbconnect.RelayEncryptionScheme) EncryptionScheme {
	switch pb {
	case pbconnect.RelayEncryptionScheme_EncryptionNone:
		return NoEncryption
	case pbconnect.RelayEncryptionScheme_TLS:
		return TLSEncryption
	case pbconnect.RelayEncryptionScheme_DHX25519_CHACHAPOLY:
		return DHXCPEncryption
	default:
		panic(fmt.Sprintf("invalid encryption scheme: %d", pb))
	}
}

func ParseEncryptionScheme(s string) (EncryptionScheme, error) {
	switch s {
	case NoEncryption.string:
		return NoEncryption, nil
	case TLSEncryption.string:
		return TLSEncryption, nil
	case DHXCPEncryption.string:
		return DHXCPEncryption, nil
	default:
		return EncryptionScheme{}, fmt.Errorf("invalid encryption scheme '%s'", s)
	}
}

func (e EncryptionScheme) PB() pbconnect.RelayEncryptionScheme {
	switch e {
	case NoEncryption:
		return pbconnect.RelayEncryptionScheme_EncryptionNone
	case TLSEncryption:
		return pbconnect.RelayEncryptionScheme_TLS
	case DHXCPEncryption:
		return pbconnect.RelayEncryptionScheme_DHX25519_CHACHAPOLY
	default:
		panic(fmt.Sprintf("invalid encryption scheme: %s", e.string))
	}
}

func PBFromEncryptions(schemes []EncryptionScheme) []pbconnect.RelayEncryptionScheme {
	pbs := make([]pbconnect.RelayEncryptionScheme, len(schemes))
	for i, sc := range schemes {
		pbs[i] = sc.PB()
	}
	return pbs
}

func EncryptionsFromPB(pbs []pbconnect.RelayEncryptionScheme) []EncryptionScheme {
	schemes := make([]EncryptionScheme, len(pbs))
	for i, s := range pbs {
		schemes[i] = EncryptionFromPB(s)
	}
	return schemes
}

func SelectEncryptionScheme(dst []EncryptionScheme, src []EncryptionScheme) (EncryptionScheme, error) {
	switch {
	case slices.Contains(dst, TLSEncryption) && slices.Contains(src, TLSEncryption):
		return TLSEncryption, nil
	case slices.Contains(dst, DHXCPEncryption) && slices.Contains(src, DHXCPEncryption):
		return DHXCPEncryption, nil
	case slices.Contains(dst, NoEncryption) && slices.Contains(src, NoEncryption):
		return NoEncryption, nil
	default:
		return EncryptionScheme{}, fmt.Errorf("no shared encryption schemes")
	}
}

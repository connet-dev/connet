package model

import (
	"fmt"
	"slices"

	"github.com/connet-dev/connet/pbc"
)

type EncryptionScheme struct{ string }

var (
	NoEncryption  = EncryptionScheme{"none"}
	TLSEncryption = EncryptionScheme{"tls"}
)

func EncryptionFromPB(pb pbc.RelayEncryptionScheme) EncryptionScheme {
	switch pb {
	case pbc.RelayEncryptionScheme_EncryptionNone:
		return NoEncryption
	case pbc.RelayEncryptionScheme_TLS:
		return TLSEncryption
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
	default:
		return NoEncryption, fmt.Errorf("invalid encryption scheme '%s'", s)
	}
}

func (e EncryptionScheme) PB() pbc.RelayEncryptionScheme {
	switch e {
	case NoEncryption:
		return pbc.RelayEncryptionScheme_EncryptionNone
	case TLSEncryption:
		return pbc.RelayEncryptionScheme_TLS
	default:
		panic(fmt.Sprintf("invalid encryption scheme: %s", e.string))
	}
}

func PBFromEncryptions(schemes []EncryptionScheme) []pbc.RelayEncryptionScheme {
	pbs := make([]pbc.RelayEncryptionScheme, len(schemes))
	for i, sc := range schemes {
		pbs[i] = sc.PB()
	}
	return pbs
}

func EncryptionsFromPB(pbs []pbc.RelayEncryptionScheme) []EncryptionScheme {
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
	case slices.Contains(dst, NoEncryption) && slices.Contains(src, NoEncryption):
		return NoEncryption, nil
	default:
		return NoEncryption, fmt.Errorf("no shared encryption schemes")
	}
}

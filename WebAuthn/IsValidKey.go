package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
)

func IsValidES256CoseKey(publicKeyMap map[int64]any) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()

	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(publicKeyMap[-2].([]byte)),
		Y:     big.NewInt(0).SetBytes(publicKeyMap[-3].([]byte)),
	}
	_, err := publicKey.ECDH()

	return publicKeyMap[3].(int64) == -7 && publicKeyMap[-1].(uint64) == 1 && err == nil && publicKeyMap[1].(uint64) == 2
}

func IsValidEdDsaCoseKey(publicKeyMap map[int64]any) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()

	var publicKey ed25519.PublicKey = publicKeyMap[-2].([]byte)

	return publicKeyMap[1].(uint64) == 1 && publicKeyMap[3].(int64) == -8 && publicKeyMap[-1].(uint64) == 6 && len(publicKey) == 32
}

func IsValidRS256CoseKey(publicKeyMap map[int64]any) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return len(publicKeyMap[-2].([]byte)) > 0 && publicKeyMap[1].(uint64) == 3 && publicKeyMap[3].(int64) == -257 && len(publicKeyMap[-1].([]byte)) > 0
}

func IsValidCoseKey(publicKeyMap map[int64]any) bool {
	return IsValidES256CoseKey(publicKeyMap) || IsValidEdDsaCoseKey(publicKeyMap) || IsValidRS256CoseKey(publicKeyMap)
}

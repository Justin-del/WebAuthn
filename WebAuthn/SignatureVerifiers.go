package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

/*
binaryConcatenation refers to the binary concatenation of authData and hash.
*/
func IsSignatureVerified(signature []byte, binaryConcatenation []byte, credentialPublicKey []byte) bool {
	var decodedPublicKeyMap map[int64]any

	cbor.Unmarshal(credentialPublicKey, &decodedPublicKeyMap)

	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(32).SetBytes(decodedPublicKeyMap[-2].([]byte)),
		Y:     big.NewInt(32).SetBytes(decodedPublicKeyMap[-3].([]byte)),
	}
	hash := sha256.Sum256(binaryConcatenation)
	hashBytes := hash[:]
	return ecdsa.VerifyASN1(&publicKey, hashBytes, signature)
}

package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
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

	//Handle for ES256 public key.
	if decodedPublicKeyMap[3].(int64) == -7 {
		publicKey := ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0).SetBytes(decodedPublicKeyMap[-2].([]byte)),
			Y:     big.NewInt(0).SetBytes(decodedPublicKeyMap[-3].([]byte)),
		}
		hash := sha256.Sum256(binaryConcatenation)
		hashBytes := hash[:]
		return ecdsa.VerifyASN1(&publicKey, hashBytes, signature)
	}

	//Handle for EdDsa public key.
	if decodedPublicKeyMap[3].(int64) == -8 {
		return ed25519.Verify(credentialPublicKey, binaryConcatenation, signature)
	}

	//Handle for RS256 public key.
	if decodedPublicKeyMap[3].(int64) == -257 {
		exponent := decodedPublicKeyMap[-2].([]byte)
		publicKey := rsa.PublicKey{
			N: big.NewInt(0).SetBytes(decodedPublicKeyMap[-1].([]byte)),
			E: int(big.NewInt(0).SetBytes(exponent).Int64()),
		}
		hash := sha256.Sum256(binaryConcatenation)
		hashBytes := hash[:]
		return rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashBytes, signature) == nil
	}

	return false
}

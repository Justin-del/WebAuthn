package webauthn_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"maps"

	webauthn "github.com/Justin-del/WebAuthn/WebAuthn"
)

func MakeCopy(original map[int64]any) map[int64]any {
	var newMap = make(map[int64]any)

	maps.Copy(newMap, original)

	return newMap
}

const crv int64 = -1
const kty int64 = 1

func TestIsValidES256CoseKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Fatalf("Failed to generate a private key.")
	}

	//Positive test begins.
	validPublicKeyMap := make(map[int64]any)
	validPublicKeyMap[3] = int64(-7)
	validPublicKeyMap[kty] = uint64(2)
	validPublicKeyMap[crv] = uint64(1)
	validPublicKeyMap[-2] = privateKey.PublicKey.X.Bytes()
	validPublicKeyMap[-3] = privateKey.PublicKey.Y.Bytes()

	if !webauthn.IsValidES256CoseKey(validPublicKeyMap) {
		t.Fatalf("Expected true but got false.")
	}
	//Positive test ends

	//Negative test for invalid publicKeyMap[3] begins.
	invalidPublicKeyMap := MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[3] = int64(-9)
	if webauthn.IsValidES256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for invalid publicKeyMap[3] ends.

	//Negative test for invalid publicKeyMap[kty] begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[kty] = int64(-9)
	if webauthn.IsValidES256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for invalid publicKeyMap[kty] ends.

	//Negative test for invalid publicKeyMap[crv] begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[crv] = int64(-9)
	if webauthn.IsValidES256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for invalid publicKeyMap[crv] ends.

	//Negative test for invalid publicKeyMap[-2] begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[-2] = make([]byte, 32)
	if webauthn.IsValidES256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for invalid publicKeyMap[-2] ends.

	//Negative test for invalid publicKeyMap[-3] begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[-3] = make([]byte, 32)
	if webauthn.IsValidES256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for invalid publicKeyMap[-3] ends.
}

func TestIsValidEdDsaCoseKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate a public and private key pair.")
	}

	//Positive test begins.
	validPublicKeyMap := make(map[int64]any)
	validPublicKeyMap[3] = int64(-8)
	validPublicKeyMap[crv] = uint64(6)
	validPublicKeyMap[kty] = uint64(1)
	validPublicKeyMap[-2] = []byte(publicKey)

	if !webauthn.IsValidEdDsaCoseKey(validPublicKeyMap) {
		t.Fatalf("Expected true but got false.")
	}
	//Positive test ends.

	//Negative test for invalidPublicKeyMap[3] begins.
	invalidPublicKeyMap := MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[3] = int64(-9)
	if webauthn.IsValidEdDsaCoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for invalidPublicKeyMap[3] ends.

	//Negative test for invalidPublicKeyMap[crv] begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[crv] = int64(-9)
	if webauthn.IsValidEdDsaCoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for invalidPublicKeyMap[crv] ends.

	//Negative test for invalidPublicKeyMap[kty] begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[kty] = int64(-9)
	if webauthn.IsValidEdDsaCoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for invalidPublicKeyMap[kty] ends.

	//Test for invalid x coordinates of public key map begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[-2] = []byte{}
	if webauthn.IsValidEdDsaCoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
}

func TestIsValidRS256CoseKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	publicKey := privateKey.PublicKey

	//Positive test begins.
	validPublicKeyMap := make(map[int64]any)
	validPublicKeyMap[3] = int64(-257)
	validPublicKeyMap[1] = uint64(3)
	validPublicKeyMap[-1] = publicKey.N.Bytes()
	validPublicKeyMap[-2] = big.NewInt(int64(publicKey.E)).Bytes()

	if !webauthn.IsValidRS256CoseKey(validPublicKeyMap) {
		t.Fatalf("Expected true but got false.")
	}

	//Positive test ends.

	//Negative test for incorrect algorithm begins.
	invalidPublicKeyMap := MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[3] = int64(-9)
	if webauthn.IsValidRS256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for incorrect algorithm ends.

	//Negative test for wrong key type begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[1] = int64(-9)
	if webauthn.IsValidRS256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for wrong key type ends.

	//Negative test for incorrect modulus begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[-1] = int64(-9)
	if webauthn.IsValidRS256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for incorrect modulus ends.

	//Negative test for incorrect public exponent begins.
	invalidPublicKeyMap = MakeCopy(validPublicKeyMap)
	invalidPublicKeyMap[-2] = int64(-9)
	if webauthn.IsValidRS256CoseKey(invalidPublicKeyMap) {
		t.Fatalf("Expected false but got true.")
	}
	//Negative test for incorrect public exponent ends.
}

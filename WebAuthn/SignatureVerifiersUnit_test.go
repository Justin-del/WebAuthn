package webauthn_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"

	"crypto/rand"
	"testing"

	"crypto/sha256"

	webauthn "github.com/Justin-del/WebAuthn/WebAuthn"
	"github.com/fxamacker/cbor/v2"
)

func TestCanVerifyES256CoseEncodedCredentialPublicKey(t *testing.T) {
	message := make([]byte, 32)
	hash := sha256.Sum256(message)

	var decodedPublicKeyMap map[int64]any = make(map[int64]any)

	decodedPublicKeyMap[1] = uint64(2)
	decodedPublicKeyMap[3] = int64(-7)
	decodedPublicKeyMap[-1] = uint64(1)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Fatalf("Got an error: %s", err.Error())
	}

	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])

	if err != nil {
		t.Fatalf("Got an error: %s", err.Error())
	}

	decodedPublicKeyMap[-2] = key.PublicKey.X.Bytes()
	decodedPublicKeyMap[-3] = key.PublicKey.Y.Bytes()

	coseEncodedCredentialPublicKey, err := cbor.Marshal(decodedPublicKeyMap)

	if err != nil {
		t.Fatalf("Got an error: %s", err.Error())
	}

	if !webauthn.IsSignatureVerified(signature, message, coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected true but got false")
	}

	if webauthn.IsSignatureVerified(append(signature, 0), message, coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected false but got true")
	}

	if webauthn.IsSignatureVerified(signature, append(message,0), coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected false but got true")
	}

	if webauthn.IsSignatureVerified(signature, message, append(coseEncodedCredentialPublicKey,0)) {
		t.Fatalf("Expected false but got true")
	}
}


func TestCanVerifyEdDsaCoseEncodedCredentialPublicKey(t *testing.T) {
	message := make([]byte, 32)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		t.Fatalf("Error is %s", err.Error())
	}

	var decodedPublicKeyMap map[int64]any = make(map[int64]any)
	decodedPublicKeyMap[crv] = 6
	decodedPublicKeyMap[kty] = 1
	decodedPublicKeyMap[-2] = []byte(publicKey)
	decodedPublicKeyMap[3] = -8

	coseEncodedCredentialPublicKey, err := cbor.Marshal(decodedPublicKeyMap)
	if err != nil {
		t.Fatalf("Error is %s", err.Error())
	}

	signature := ed25519.Sign(privateKey, message)

	if !webauthn.IsSignatureVerified(signature, message, coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected true but got false")
	}

	if webauthn.IsSignatureVerified(append(signature, 0), message, coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected false but got true")
	}

	if webauthn.IsSignatureVerified(signature, append(message,0), coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected false but got true")
	}

	if webauthn.IsSignatureVerified(signature, message, append(coseEncodedCredentialPublicKey,0)) {
		t.Fatalf("Expected false but got true")
	}
}

func TestCanVerifyRS256CoseEncodedCredentialPublicKey(t *testing.T) {
	message := make([]byte, 32)
	hash := sha256.Sum256(message)

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)

	if err != nil {
		t.Fatalf("Error is %s", err.Error())
	}

	var decodedPublicKeyMap map[int64]any = make(map[int64]any)

	decodedPublicKeyMap[1] = uint64(3)
	decodedPublicKeyMap[3] = int64(-257)
	decodedPublicKeyMap[-1] = privateKey.PublicKey.N.Bytes()
	decodedPublicKeyMap[-2] = big.NewInt(int64(privateKey.PublicKey.E)).Bytes()

	coseEncodedCredentialPublicKey, err := cbor.Marshal(decodedPublicKeyMap)

	if err != nil {
		t.Fatalf("Error is %s", err.Error())
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])

	if err != nil {
		t.Fatalf("Error is %s", err.Error())
	}

	if !webauthn.IsSignatureVerified(signature, message, coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected true but got false.")
	}

	if webauthn.IsSignatureVerified(append(signature, 0), message, coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected false but got true")
	}

	if webauthn.IsSignatureVerified(signature, append(message,0), coseEncodedCredentialPublicKey) {
		t.Fatalf("Expected false but got true")
	}

	if webauthn.IsSignatureVerified(signature, message, append(coseEncodedCredentialPublicKey,0)) {
		t.Fatalf("Expected false but got true")
	}
}

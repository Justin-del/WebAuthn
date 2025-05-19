package webauthn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

var supportedPublicKeyAlgorithms []int = []int{-8, -7, -257}

var Rp RelyingParty = RelyingParty{
	Id:   "localhost",
	Name: "localhost",
}

func panicIfSIsNotOfExpectedValue(s string, expected []string) {
	found := slices.Contains(expected, s)
	if !found {
		panic("Value '" + s + "' is not in the list of expected values.")
	}
}

func GetBase64URLEncodedChallenge() string {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		panic("Failed to generate random challenge: " + err.Error())
	}
	encoded := base64.RawURLEncoding.EncodeToString(challenge)
	return encoded
}

func GetChallenge() []byte {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		panic("Failed to generate random challenge: " + err.Error())
	}

	return challenge
}


func ParseClientDataJSON(base64URLEncodedString string) ClientDataJSON {
	data, _ := base64.RawURLEncoding.DecodeString(base64URLEncodedString)
	var clientData ClientDataJSON

	json.Unmarshal(data, &clientData)
	return clientData
}

/*
Verification of tokenBinding.status is not done here because tokenBinding.status is not a reliable property to
depend for security purposes if not all authenticators support it.
*/
func IsClientDataJSONCorrect(clientDataJSON string, expected_origin string, expected_type string, expected_challenge []byte) bool {
	clientData := ParseClientDataJSON(clientDataJSON)
	return clientData.Origin == expected_origin && clientData.Type == expected_type && clientData.Challenge == base64.RawURLEncoding.EncodeToString(expected_challenge)
}

func IsCorrectHash(hash [32]byte) bool {
	correctHash := sha256.Sum256([]byte(Rp.Id))

	return correctHash == hash
}

func AreFlagsValid(flags byte, is_user_verification_required bool) bool {
	userPresentBit := flags & 1
	userVerificationBit := flags >> 2 & 1

	if is_user_verification_required {
		return userPresentBit == 1 && userVerificationBit == 1
	} else {
		return userPresentBit == 1
	}
}

/*
The functionToSaveCredentialsIntoDatabase parameter should return true if the credential is succesfully saved and false if the credential is not succesfully saved.
This function returns true if the registration is successful and false if the registration is not succesful. The credentialId is not guaranteed to be unregistered for any user. Also, the consumer of this function must ensure that the challenge gets deleted  after it is used.
*/
func RegisterPublicKeyCredential(session *RegistrationSession, publicKeyCredential *RegistrationPublicKeyCredential, expectedOrigin string, functionToSaveCredentialsIntoDatabase func(credentialId []byte, credentialPublicKey []byte, transports []string, signCount uint32, userId []byte) bool) bool {

	isClientDataJSONCorrect := IsClientDataJSONCorrect(publicKeyCredential.Response.ClientDataJSON, expectedOrigin, "webauthn.create", session.Challenge)
	var attestationObject AttestationObject

	base64DecodedAttestationSlice, err := base64.RawURLEncoding.DecodeString(publicKeyCredential.Response.AttestationObject)

	if err != nil {
		return false
	}

	err = cbor.Unmarshal(base64DecodedAttestationSlice, &attestationObject)

	if err != nil {
		return false
	}

	credentialIdLength := binary.BigEndian.Uint16(attestationObject.AuthData[53:55])
	credentialId := attestationObject.AuthData[55 : 55+credentialIdLength]
	credentialPublicKey := attestationObject.AuthData[55+credentialIdLength:]

	var credentialPublicKeyMap map[int64]any

	err = cbor.Unmarshal(credentialPublicKey, &credentialPublicKeyMap)
	if err != nil {
		return false
	}

	canRegister := isClientDataJSONCorrect && IsCorrectHash([32]byte(attestationObject.AuthData[0:32])) && AreFlagsValid(attestationObject.AuthData[32], session.UserVerification == "required") && IsValidKey(credentialPublicKeyMap)

	if canRegister {
		return functionToSaveCredentialsIntoDatabase(credentialId, credentialPublicKey, publicKeyCredential.Response.Transports, binary.BigEndian.Uint32(attestationObject.AuthData[33:37]), session.UserId)
	} else {
		return false
	}

}

/*
This function will return an AuthenticationResult where each field is set to their default value if there is an error. It is the consumer's responsibility to ensure that the storedCredential belongs to the user. If the user is identified before the authentication ceremony is began, then please verify that the UserHandle of publicKeyCredential.Response maps to the current user.
*/
func AuthenticatePublicKeyCredential(session *AuthenticationSession, allowCredentials []Credential, publicKeyCredential *AuthenticationPublicKeyCredential, storedCredential *StoredCredential, expectedOrigin string, functionToSaveSignCount func(credentialId []byte, signCount int)) AuthenticationResult {
	//If options.allowCredentials is not empty, verify that credential.id identifies one of the public key credentials listed in allowCredentials.
	found := len(allowCredentials) == 0
	for _, cred := range allowCredentials {
		if cred.Id == publicKeyCredential.RawId {
			found = true
			break
		}
	}

	if !found {
		return AuthenticationResult{}
	}

	isClientDataJSONCorrect := IsClientDataJSONCorrect(publicKeyCredential.Response.ClientDataJSON, expectedOrigin, "webauthn.get", session.Challenge)
	authData, err := base64.RawURLEncoding.DecodeString(publicKeyCredential.Response.AuthenticatorData)

	if err != nil {
		return AuthenticationResult{}
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(publicKeyCredential.Response.Signature)

	if err != nil {
		return AuthenticationResult{}
	}

	clientDataBytes, err := base64.RawURLEncoding.DecodeString(publicKeyCredential.Response.ClientDataJSON)

	if err != nil {
		return AuthenticationResult{}
	}
	hash := sha256.Sum256([]byte(clientDataBytes))

	cloneWarning := false
	signatureCounterOfAuthenticator := binary.BigEndian.Uint32(authData[33:37])

	if storedCredential.SignatureCounter != 0 || signatureCounterOfAuthenticator != 0 {
		cloneWarning = signatureCounterOfAuthenticator <= uint32(storedCredential.SignatureCounter)
	}

	if !cloneWarning {
		credentialId, err := base64.RawURLEncoding.DecodeString(publicKeyCredential.RawId)
		if err != nil {
			return AuthenticationResult{}
		}
		functionToSaveSignCount(credentialId, int(signatureCounterOfAuthenticator))
	}

	return AuthenticationResult{
		CloneWarning:              cloneWarning,
		AreEssentialStepsVerified: isClientDataJSONCorrect && IsCorrectHash([32]byte(authData[0:32])) && AreFlagsValid(authData[32], session.UserVerification == "required") && IsSignatureVerified(signatureBytes, append(authData, hash[:]...), storedCredential.CredentialPublicKey),
	}
}

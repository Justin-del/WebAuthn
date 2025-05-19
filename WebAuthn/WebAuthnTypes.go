package webauthn

import "github.com/fxamacker/cbor/v2"

type RegistrationSession struct {
	Challenge        []byte
	UserVerification string
	/*
		The UserId is not guaranteed to be available.
	*/
	UserId []byte
}

type AuthenticationSession struct {
	Challenge        []byte
	UserVerification string
}

type AuthenticatorSelection struct {
	/**
	It can be either be "platform"|"cross-platform"|"".
	*/
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	/*
		It can either be "discouraged"|"preferred"|"required". See https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions for more info.
	*/
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

type Credential struct {
	/*
		Id is base64 url encoded
	*/
	Id         string   `json:"id"`
	Transports []string `json:"transports"`
	Type       string   `json:"type"`
}

type StoredCredential struct {
	SignatureCounter    int
	CredentialPublicKey []byte
}

type AuthenticationResult struct {
	CloneWarning              bool
	AreEssentialStepsVerified bool
}

type RelyingParty struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type PublicKey struct {
	/*
		Alg corresponds to the COSE registry
	*/
	Alg int `json:"alg"`

	/*
		Type can only be public-key for now.
	*/
	Type string `json:"type"`
}

type PublicKeyCredentialCreationOptions struct {
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	/*
		Challenge is base64 url encoded
	*/
	Challenge          string       `json:"challenge"`
	ExcludeCredentials []Credential `json:"excludeCredentials,omitempty"`
	PubKeyCredParams   []PublicKey  `json:"pubKeyCredParams"`
	Rp                 RelyingParty `json:"rp"`
	/*
		Timeout is in milliseconds.
	*/
	Timeout int      `json:"timeout"`
	User    User     `json:"user"`
	Hints   []string `json:"hints,omitempty"`
}

type PublicKeyCredentialRequestOptions struct {
	AllowedCredentials []Credential `json:"allowedCredentials"`
	/*
		Challenge is base64 url encoded
	*/
	Challenge string `json:"challenge"`
	/*
		An array of strings where each value in the array can either be "security-key" or "client-device" or "hybrid". See https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions for more info.
	*/
	Hints []string `json:"hints,omitempty"`
	RpId  string   `json:"rpId,omitempty"`
	/*
		Must be in milliseconds
	*/
	Timeout int `json:"timeout"`
	/*
		Can be 'required'|'preferred'|'discouraged'.
	*/
	UserVerification string `json:"userVerification"`
}

type User struct {
	DisplayName string `json:"displayName"`
	/*
		Id should be base64 url encoded.
	*/
	Id string `json:"id"`
	/*
		Used to distinguish between accounts with similar display name.
	*/
	Name string `json:"name"`
}

type AuthenticatorAttestationResponse struct {
	/*
		Base 64 url encoded
	*/
	AttestationObject string `json:"attestationObject"`
	/*
		Base 64 url encoded
	*/
	ClientDataJSON string   `json:"clientDataJSON"`
	Transports     []string `json:"transports"`
}

type AuthenticatorAssertionResponse struct {
	/*
		Base 64 url encoded
	*/
	AuthenticatorData string `json:"authenticatorData"`
	/*
		Base 64 url encoded
	*/
	ClientDataJSON string `json:"clientDataJSON"`
	/*
		Base64 url encoded
	*/
	Signature string `json:"signature"`
	/*
		Base64 url encoded
	*/
	UserHandle string `json:"userHandle"`
}

type ClientDataJSON struct {
	Type      string
	Challenge string
	Origin    string
}

type RegistrationPublicKeyCredential struct {
	Id string `json:"id"`
	/*
		base64 url-encoded version of the array buffer RawId.
	*/
	RawId                   string                           `json:"rawId"`
	AuthenticatorAttachment string                           `json:"authenticatorAttachment"`
	Type                    string                           `json:"type"`
	Response                AuthenticatorAttestationResponse `json:"response"`
}

type AuthenticationPublicKeyCredential struct {
	Id string `json:"id"`
	/*
		base64 url-encoded version of the array buffer RawId.
	*/
	RawId                   string                         `json:"rawId"`
	AuthenticatorAttachment string                         `json:"authenticatorAttachment"`
	Type                    string                         `json:"type"`
	Response                AuthenticatorAssertionResponse `json:"response"`
}

type AttestationObject struct {
	Fmt      string          `cbor:"fmt"`
	AttStmt  cbor.RawMessage `cbor:"attStmt"`
	AuthData []byte          `cbor:"authData"`
}

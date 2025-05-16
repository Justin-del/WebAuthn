package webauthn

type Attestation string

const (
	None Attestation = "none"
)

type PublicKeyCredentialCreationOptions struct {
	attestation Attestation
}

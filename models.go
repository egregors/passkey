package passkey

import "github.com/go-webauthn/webauthn/webauthn"

type transientUser struct {
	id   []byte
	name string
}

func (u *transientUser) WebAuthnID() []byte                         { return u.id }
func (u *transientUser) WebAuthnName() string                       { return u.name }
func (u *transientUser) WebAuthnDisplayName() string                { return u.name }
func (u *transientUser) WebAuthnCredentials() []webauthn.Credential { return nil }

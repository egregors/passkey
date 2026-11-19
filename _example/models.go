package main

import (
	"bytes"
	"slices"

	"github.com/go-webauthn/webauthn/webauthn"
)

type User struct {
	ID          []byte
	DisplayName string
	Name        string

	creds []webauthn.Credential
}

func (u *User) WebAuthnID() []byte {
	return u.ID
}

func (u *User) WebAuthnName() string {
	return u.Name
}

func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

func (u *User) snapshot() *User {
	snapshot := *u
	snapshot.ID = bytes.Clone(u.ID)
	snapshot.creds = slices.Clone(u.creds)
	for i := range snapshot.creds {
		c := &snapshot.creds[i]
		c.ID = bytes.Clone(c.ID)
		c.PublicKey = bytes.Clone(c.PublicKey)
		c.Transport = slices.Clone(c.Transport)
		c.Authenticator.AAGUID = bytes.Clone(c.Authenticator.AAGUID)
		c.Attestation.ClientDataJSON = bytes.Clone(c.Attestation.ClientDataJSON)
		c.Attestation.ClientDataHash = bytes.Clone(c.Attestation.ClientDataHash)
		c.Attestation.AuthenticatorData = bytes.Clone(c.Attestation.AuthenticatorData)
		c.Attestation.Object = bytes.Clone(c.Attestation.Object)
	}
	return &snapshot
}

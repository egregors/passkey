package main

import "github.com/go-webauthn/webauthn/webauthn"

type User struct {
	ID          []byte
	Name        string
	DisplayName string

	creds []webauthn.Credential
}

func New(ID []byte, name, displayName string) *User {
	return &User{
		ID:          ID,
		Name:        name,
		DisplayName: displayName,
		creds:       make([]webauthn.Credential, 0, 0),
	}
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

func (u *User) AddCredential(credential webauthn.Credential) {
	u.creds = append(u.creds, credential)
}

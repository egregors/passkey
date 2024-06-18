package main

import "github.com/go-webauthn/webauthn/webauthn"

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

func (u *User) WebAuthnIcon() string {
	return "https://pics.com/avatar.png"
}

func (u *User) PutCredential(credential webauthn.Credential) {
	u.creds = append(u.creds, credential)
}

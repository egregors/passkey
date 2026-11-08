package main

import (
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/egregors/passkey"
)

func testCredential() webauthn.Credential {
	return webauthn.Credential{
		ID: []byte("key"), PublicKey: []byte("public key"),
		Transport:     []protocol.AuthenticatorTransport{protocol.USB},
		Authenticator: webauthn.Authenticator{SignCount: 1, AAGUID: []byte("aaguid")},
		Attestation: webauthn.CredentialAttestation{
			ClientDataJSON: []byte("client data"), ClientDataHash: []byte("hash"),
			AuthenticatorData: []byte("auth data"), Object: []byte("attestation"),
		},
	}
}

func TestUserStoreCredentialUpdate(t *testing.T) {
	store := NewUserStore()
	_, err := store.Create(passkey.NewUser{Username: "user", UserID: []byte("user"), Credential: testCredential()})
	require.NoError(t, err)
	updated := testCredential()
	updated.Authenticator.SignCount = 20
	updated.Flags = webauthn.NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified)
	updated.PublicKey = []byte("must not replace registered key")
	for range 3 {
		require.NoError(t, store.UpdateCredential([]byte("user"), updated))
	}
	stale := testCredential()
	stale.Authenticator.SignCount = 15
	stale.Authenticator.CloneWarning = true
	require.NoError(t, store.UpdateCredential([]byte("user"), stale))
	u, err := store.Get([]byte("user"))
	require.NoError(t, err)
	creds := u.WebAuthnCredentials()
	require.Len(t, creds, 1)
	want := testCredential()
	want.Authenticator.SignCount = 20
	want.Authenticator.CloneWarning = true
	want.Flags = updated.Flags
	assert.Equal(t, want, creds[0])
	require.NoError(t, store.UpdateCredential([]byte("user"), updated))
	u, err = store.Get([]byte("user"))
	require.NoError(t, err)
	assert.True(t, u.WebAuthnCredentials()[0].Authenticator.CloneWarning)
	require.ErrorIs(t, store.UpdateCredential([]byte("missing"), updated), passkey.ErrUserNotFound)
	updated.ID = []byte("missing")
	require.ErrorIs(t, store.UpdateCredential([]byte("user"), updated), passkey.ErrCredentialNotFound)
	_, err = store.Create(passkey.NewUser{Username: "other", UserID: []byte("user"), Credential: testCredential()})
	require.ErrorIs(t, err, passkey.ErrUserAlreadyExists)
}

func TestUserStoreDetachedSnapshots(t *testing.T) {
	store := NewUserStore()
	input := passkey.NewUser{Username: "user", UserID: []byte("user"), Credential: testCredential()}
	created, err := store.Create(input)
	require.NoError(t, err)
	byID, err := store.Get([]byte("user"))
	require.NoError(t, err)
	byName, err := store.GetByName("user")
	require.NoError(t, err)
	input.UserID[0] = 'x'
	input.Credential.PublicKey[0] = 'x'
	for _, snapshot := range []passkey.User{created, byID, byName} {
		snapshot.WebAuthnID()[0] = 'x'
		c := &snapshot.WebAuthnCredentials()[0]
		c.ID[0] = 'x'
		c.PublicKey[0] = 'x'
		c.Transport[0] = protocol.NFC
		c.Authenticator.AAGUID[0] = 'x'
		c.Attestation.ClientDataJSON[0] = 'x'
		c.Attestation.ClientDataHash[0] = 'x'
		c.Attestation.AuthenticatorData[0] = 'x'
		c.Attestation.Object[0] = 'x'
	}
	stored, err := store.Get([]byte("user"))
	require.NoError(t, err)
	assert.Equal(t, []byte("user"), stored.WebAuthnID())
	assert.Equal(t, []webauthn.Credential{testCredential()}, stored.WebAuthnCredentials())
}

func TestUserStoreConcurrentCredentialUpdates(t *testing.T) {
	store := NewUserStore()
	_, err := store.Create(passkey.NewUser{Username: "user", UserID: []byte("user"), Credential: testCredential()})
	require.NoError(t, err)
	second := testCredential()
	second.ID = []byte("second")
	store.users["user"].creds = append(store.users["user"].creds, second)
	var wg sync.WaitGroup
	for _, id := range []string{"key", "second"} {
		for _, reverse := range []bool{false, true} {
			wg.Go(func() {
				for i := 1; i <= 100; i++ {
					c := testCredential()
					c.ID = []byte(id)
					c.Authenticator.SignCount = uint32(i)
					if reverse {
						c.Authenticator.SignCount = uint32(101 - i)
					}
					assert.NoError(t, store.UpdateCredential([]byte("user"), c))
				}
			})
		}
	}
	wg.Go(func() {
		for range 100 {
			u, getErr := store.Get([]byte("user"))
			if assert.NoError(t, getErr) {
				u.WebAuthnID()[0] = 'x'
				for _, c := range u.WebAuthnCredentials() {
					c.PublicKey[0] = 'x'
				}
			}
		}
	})
	wg.Wait()
	u, err := store.Get([]byte("user"))
	require.NoError(t, err)
	creds := u.WebAuthnCredentials()
	require.Len(t, creds, 2)
	for i, id := range []string{"key", "second"} {
		assert.Equal(t, []byte(id), creds[i].ID)
		assert.Equal(t, uint32(100), creds[i].Authenticator.SignCount)
		assert.Equal(t, testCredential().PublicKey, creds[i].PublicKey)
	}
}

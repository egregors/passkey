package passkey

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/egregors/passkey/deps"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistrationRejectsExistingUser(t *testing.T) {
	for _, upsert := range []bool{false, true} {
		t.Run(fmt.Sprintf("upsert=%t", upsert), func(t *testing.T) {
			users := NewMockUserStore(t)
			if upsert {
				user := NewMockUser(t)
				user.EXPECT().WebAuthnName().Return("existing")
				user.EXPECT().WebAuthnCredentials().Return([]webauthn.Credential{{ID: []byte("original")}})
				users.EXPECT().Create("existing").Return(user, nil).Once()
			} else {
				users.EXPECT().Create("existing").Return(nil, fmt.Errorf("insert user: %w", ErrUserAlreadyExists)).Once()
			}
			p, err := New(Config{
				WebauthnConfig: &webauthn.Config{RPDisplayName: "Test", RPID: "localhost", RPOrigins: []string{"http://localhost"}},
				UserStore:      users, AuthSessionStore: NewMockSessionStore[webauthn.SessionData](t),
				UserSessionStore: NewMockSessionStore[UserSessionData](t),
			})
			require.NoError(t, err)
			p.webAuthn = deps.NewMockWebAuthnInterface(t)
			mux := http.NewServeMux()
			p.MountRoutes(mux, "/api/")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api"+pathRegisterBegin, body("username", "existing")))
			assert.Equal(t, http.StatusConflict, w.Code)
			assert.Contains(t, w.Body.String(), ErrUserAlreadyExists.Error())
			assert.Empty(t, w.Result().Cookies())
			// Unconfigured mocks fail if a challenge/session is created or the user is updated.
		})
	}
}

func TestRegistrationFinishRejectsExistingCredentials(t *testing.T) {
	user := NewMockUser(t)
	user.EXPECT().WebAuthnName().Return("existing")
	user.EXPECT().WebAuthnCredentials().Return([]webauthn.Credential{{ID: []byte("original")}})
	users := NewMockUserStore(t)
	users.EXPECT().Get([]byte("existing-id")).Return(user, nil).Once()
	ceremonies := NewMockSessionStore[webauthn.SessionData](t)
	ceremonies.EXPECT().Get("old-ceremony").Return(&webauthn.SessionData{UserID: []byte("existing-id")}, true).Once()
	ceremonies.EXPECT().Delete("old-ceremony").Once()
	p, err := New(Config{
		WebauthnConfig: &webauthn.Config{RPDisplayName: "Test", RPID: "localhost", RPOrigins: []string{"http://localhost"}},
		UserStore:      users, AuthSessionStore: ceremonies, UserSessionStore: NewMockSessionStore[UserSessionData](t),
	})
	require.NoError(t, err)
	p.webAuthn = deps.NewMockWebAuthnInterface(t)
	mux := http.NewServeMux()
	p.MountRoutes(mux, "/api/")
	r := httptest.NewRequest(http.MethodPost, "/api"+pathRegisterFinish, http.NoBody)
	r.AddCookie(&http.Cookie{Name: p.cookieSettings.authSessionName, Value: "old-ceremony"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), ErrUserAlreadyExists.Error())
	// No FinishRegistration, PutCredential, or Update call is permitted.
}

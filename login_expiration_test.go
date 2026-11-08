package passkey

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBeginLoginServerExpiration(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enforce bool
		timeout time.Duration
		wantTTL time.Duration
	}{
		{"default configuration", false, 0, 5 * time.Minute},
		{"client timeout only", false, time.Minute, 5 * time.Minute},
		{"shorter WebAuthn deadline", true, time.Minute, time.Minute},
		{"longer WebAuthn deadline capped", true, 10 * time.Minute, 5 * time.Minute},
	} {
		t.Run(tt.name, func(t *testing.T) {
			user := NewMockUser(t)
			user.On("WebAuthnID").Return([]byte("expiry-user"))
			user.On("WebAuthnName").Return("expiry-user")
			user.On("WebAuthnCredentials").Return([]webauthn.Credential{{ID: []byte("credential")}})
			users := NewMockUserStore(t)
			users.On("GetByName", "expiry-user").Return(user, nil).Once()
			sessions := &loginReplayStore[webauthn.SessionData]{data: make(map[string]webauthn.SessionData)}
			p, err := New(Config{
				WebauthnConfig: &webauthn.Config{
					RPID: "example.com", RPDisplayName: "test", RPOrigins: []string{"https://example.com"},
					Timeouts: webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: tt.enforce, Timeout: tt.timeout}},
				},
				UserStore: users, LoginSessionStore: sessions,
				RegistrationSessionStore: NewMockSessionStore[RegistrationSessionData](t),
				UserSessionStore:         NewMockSessionStore[UserSessionData](t),
			})
			require.NoError(t, err)
			before := time.Now()
			rec := httptest.NewRecorder()
			p.mux.ServeHTTP(rec, withAllowedOrigin(httptest.NewRequest(http.MethodPost, pathLoginBegin, body("username", "expiry-user"))))
			after := time.Now()
			require.Equal(t, http.StatusOK, rec.Code)
			cookies := rec.Result().Cookies()
			require.Len(t, cookies, 1)
			assert.Equal(t, p.cookieSettings.loginSessionName, cookies[0].Name)
			assert.Equal(t, 300, cookies[0].MaxAge)
			session, ok := sessions.Get(cookies[0].Value)
			require.True(t, ok)
			require.NotNil(t, session)
			require.False(t, session.Expires.IsZero())
			assert.GreaterOrEqual(t, session.Expires.Sub(before), tt.wantTTL)
			assert.LessOrEqual(t, session.Expires.Sub(after), tt.wantTTL)
		})
	}
}

func TestFinishLoginServerExpiration(t *testing.T) {
	for _, tt := range []struct {
		name      string
		expires   func() time.Time
		wantValid bool
	}{
		{"legacy session without expiration", func() time.Time { return time.Time{} }, false},
		{"expired session", func() time.Time { return time.Now().Add(-time.Minute) }, false},
		{"deadline reached", time.Now, false},
		{"unexpired session", func() time.Time { return time.Now().Add(time.Minute) }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newLoginReplayFixture(t)
			// Keep the real challenge and signed assertion, changing only the stored deadline.
			session, ok := f.p.loginSessionStore.Consume(f.token)
			require.True(t, ok)
			require.NotNil(t, session)
			session.Expires = tt.expires()
			token, err := f.p.loginSessionStore.Create(*session)
			require.NoError(t, err)
			f.token = token
			// Optional expectations let this test demonstrate the original vulnerability,
			// while call counts below enforce rejection before any user access.
			f.users.On("Get", f.userID).Return(f.user, nil).Maybe()
			f.users.On("UpdateCredential", f.userID, mock.AnythingOfType("webauthn.Credential")).Return(nil).Maybe()
			rec := f.finish(f.assertion) // Sends the saved cookie manually, independent of browser expiry.
			wantCalls := 0
			if tt.wantValid {
				assert.Equal(t, http.StatusOK, rec.Code)
				wantCalls = 1
			} else {
				assert.Equal(t, http.StatusBadRequest, rec.Code)
				assert.JSONEq(t, `"invalid request"`, rec.Body.String())
			}
			assertLoginCookieCleared(t, f.p, rec)
			f.users.AssertNumberOfCalls(t, "Get", wantCalls)
			f.users.AssertNumberOfCalls(t, "UpdateCredential", wantCalls)
			assert.Equal(t, wantCalls, f.authSessions.count())
			_, ok = f.p.loginSessionStore.Get(f.token)
			assert.False(t, ok, "expired and legacy sessions must also be consumed")

			replay := f.finish(f.assertion)
			assert.Equal(t, http.StatusBadRequest, replay.Code)
			assert.JSONEq(t, `"invalid request"`, replay.Body.String())
			assertLoginCookieCleared(t, f.p, replay)
			assert.Equal(t, wantCalls, f.authSessions.count())
		})
	}
}

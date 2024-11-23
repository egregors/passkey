package passkey

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

func TestPasskey_Logout(t *testing.T) {
	tests := []struct {
		name         string
		sessionStore func() SessionStore
		l            func() Logger
		w            http.ResponseWriter
		r            func() *http.Request
	}{
		{
			name: "succ: delete session",
			sessionStore: func() SessionStore {
				mock := NewMockSessionStore(t)

				mock.EXPECT().
					Delete("hello-darkness-my-old-friend").
					Times(1)

				return mock
			},
			l: func() Logger {
				mock := NewMockLogger(t)

				return mock
			},
			w: httptest.NewRecorder(),
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
				r.AddCookie(&http.Cookie{
					Name:  defaultAuthSessionName,
					Value: "hello-darkness-my-old-friend",
				})

				return r
			},
		},
		{
			name: "err: can't get session cookie",
			sessionStore: func() SessionStore {
				return NewMockSessionStore(t)
			},
			l: func() Logger {
				mock := NewMockLogger(t)

				mock.EXPECT().
					Errorf("can't get session cookie: %s", "cookie not found").
					Times(1)

				return mock
			},
			w: httptest.NewRecorder(),
			r: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(
				Config{
					WebauthnConfig: &webauthn.Config{
						RPDisplayName: "Passkey Test",
						RPID:          "localhost",
						RPOrigins:     []string{"localhost"},
					},
					UserStore:         nil,
					AuthSessionStore:  tt.sessionStore(),
					UserSessionMaxAge: 69,
				},
			)
			assert.NoError(t, err)
			p.Logout(tt.w, tt.r())
		})
	}
}

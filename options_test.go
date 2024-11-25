package passkey

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithLogger(t *testing.T) {
	p := &Passkey{}
	setupDefaultOptions(p)

	defaultLogger := p.log
	customLogger := NewMockLogger(t)

	tests := []struct {
		name string
		l    Logger
		want Logger
	}{
		{
			name: "err: nil (default logger should be used)",
			l:    nil,
			want: defaultLogger,
		},
		{
			name: "succ: custom logger",
			l:    customLogger,
			want: customLogger,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithLogger(tt.l)
			opt(p)

			assert.Equal(t, tt.want, p.log)
		})
	}
}

func Test_camelCaseConcat(t *testing.T) {
	tests := []struct {
		name string
		ws   []string
		want string
	}{
		{
			name: "empty",
			ws:   []string{},
			want: "",
		},
		{
			name: "single",
			ws:   []string{"hello"},
			want: "hello",
		},
		{
			name: "multiple",
			ws:   []string{"hello", "world"},
			want: "helloWorld",
		},
		{
			name: "multiple with empty",
			ws:   []string{"hello", "", "world"},
			want: "helloWorld",
		},
		{
			name: "multiple with space",
			ws:   []string{"hello", "world", " ", "how", "   ", "are", "you"},
			want: "helloWorldHowAreYou",
		},
		{
			name: "multiple with tabs",
			ws:   []string{"hello", "world", "\t", "how", "are", "you"},
			want: "helloWorldHowAreYou",
		},
		{
			name: "multiple with newlines",
			ws:   []string{"hello", "world", "\n", "how", "are", "you"},
			want: "helloWorldHowAreYou",
		},
		{
			name: "multiple with mixed",
			ws:   []string{"hello", "world", " ", "\t", "\n", "how", "are", "you"},
			want: "helloWorldHowAreYou",
		},
		{
			name: "multiple with mixed cases",
			ws:   []string{"HeLLo", "woRld", "How", "are", "yOu"},
			want: "helloWorldHowAreYou",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, camelCaseConcat(tt.ws...), "camelCaseConcat(%v)", tt.ws)
		})
	}
}

func TestWithInsecureCookie(t *testing.T) {
	// init without insecure cookie
	p, err := New(
		Config{
			WebauthnConfig: &webauthn.Config{
				RPDisplayName: "Passkey Example",
				RPID:          "localhost",
				RPOrigins:     []string{"localhost:8080"},
			},
			UserStore:        NewMockUserStore(t),
			AuthSessionStore: NewMockSessionStore[webauthn.SessionData](t),
			UserSessionStore: NewMockSessionStore[UserSessionData](t),
		},
	)
	require.NoError(t, err)
	assert.True(t, p.cookieSettings.Secure)

	// init with insecure cookie
	p, err = New(
		Config{
			WebauthnConfig: &webauthn.Config{
				RPDisplayName: "Passkey Example",
				RPID:          "localhost",
				RPOrigins:     []string{"localhost:8080"},
			},
			UserStore:        NewMockUserStore(t),
			AuthSessionStore: NewMockSessionStore[webauthn.SessionData](t),
			UserSessionStore: NewMockSessionStore[UserSessionData](t),
		},
		WithInsecureCookie(),
	)
	require.NoError(t, err)
	assert.False(t, p.cookieSettings.Secure)
}

func TestWithSessionCookieNamePrefix(t *testing.T) {
	tests := []struct {
		name                string
		prefix              string
		wantAuthSessionName string
		wantUserSessionName string
	}{
		{
			name:                "empty: default prefix will be used",
			prefix:              "",
			wantAuthSessionName: "pkAsid",
			wantUserSessionName: "pkUsid",
		},
		{
			name:                "custom prefix",
			prefix:              "custom",
			wantAuthSessionName: "customAsid",
			wantUserSessionName: "customUsid",
		},
		{
			name:                "custom prefix with space and multiple words",
			prefix:              "custom prefix",
			wantAuthSessionName: "custom prefixAsid",
			wantUserSessionName: "custom prefixUsid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(
				Config{
					WebauthnConfig: &webauthn.Config{
						RPDisplayName: "Passkey Example",
						RPID:          "localhost",
						RPOrigins:     []string{"localhost:8080"},
					},
					UserStore:        NewMockUserStore(t),
					AuthSessionStore: NewMockSessionStore[webauthn.SessionData](t),
					UserSessionStore: NewMockSessionStore[UserSessionData](t),
				},
				WithSessionCookieNamePrefix(tt.prefix),
			)
			require.NoError(t, err)
			assert.Equalf(t, tt.wantAuthSessionName, p.cookieSettings.authSessionName, "WithSessionCookieNamePrefix(%v)", tt.prefix)
			assert.Equalf(t, tt.wantUserSessionName, p.cookieSettings.userSessionName, "WithSessionCookieNamePrefix(%v)", tt.prefix)
		})
	}
}

func TestWithUserSessionMaxAge(t *testing.T) {
	tests := []struct {
		name       string
		maxAge     time.Duration
		wantMaxAge time.Duration
	}{
		{
			name:       "0",
			maxAge:     0,
			wantMaxAge: defaultUserSessionMaxAge,
		},
		{
			name:       "invalid",
			maxAge:     -1,
			wantMaxAge: defaultUserSessionMaxAge,
		},
		{
			name:       "valid",
			maxAge:     42 * time.Minute,
			wantMaxAge: 42 * time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(
				Config{
					WebauthnConfig: &webauthn.Config{
						RPDisplayName: "Passkey Example",
						RPID:          "localhost",
						RPOrigins:     []string{"localhost:8080"},
					},
					UserStore:        NewMockUserStore(t),
					AuthSessionStore: NewMockSessionStore[webauthn.SessionData](t),
					UserSessionStore: NewMockSessionStore[UserSessionData](t),
				},
				WithUserSessionMaxAge(tt.maxAge),
			)
			require.NoError(t, err)
			assert.Equalf(t, tt.wantMaxAge, p.cookieSettings.userSessionMaxAge, "WithUserSessionMaxAge(%v)", tt.maxAge)
		})
	}
}

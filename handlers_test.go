package passkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/egregors/passkey/log"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/mock"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func body(key, value string) io.Reader {
	bodyBytes, _ := json.Marshal(map[string]string{
		key: value,
	})

	return io.NopCloser(bytes.NewReader(bodyBytes))
}

func Test_getUsername(t *testing.T) {
	tests := []struct {
		name    string
		r       *http.Request
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "succ: ok",
			r:       httptest.NewRequest(http.MethodGet, "/target", body("username", "Berik the Cat")),
			want:    "Berik the Cat",
			wantErr: assert.NoError,
		},
		{
			name: "err: no username",
			r:    httptest.NewRequest(http.MethodGet, "/target", body("foo", "bar")),
			want: "",
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoUsername)
			},
		},
		{
			name: "err: empty username",
			r:    httptest.NewRequest(http.MethodGet, "/target", body("username", "")),
			want: "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoUsername)
			},
		},
		{
			name: "err: decode error",
			r:    httptest.NewRequest(http.MethodGet, "/target", io.NopCloser(bytes.NewReader([]byte("invalid json")))),
			want: "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "invalid character 'i' looking for beginning of value")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getUsername(tt.r)
			if !tt.wantErr(t, err, fmt.Sprintf("getUsername(%v)", tt.r)) {
				return
			}
			assert.Equalf(t, tt.want, got, "getUsername(%v)", tt.r)
		})
	}
}

func TestPasskey_beginRegistration(t *testing.T) {
	log.Info.Off()
	log.Debg.Off()

	defer func() {
		log.Info.On()
		log.Debg.On()
	}()

	user := NewMockUser(t)
	user.EXPECT().
		WebAuthnID().
		Return([]byte("1234-5678-9012-3456"))

	user.EXPECT().
		WebAuthnDisplayName().
		Return("Berik the Cat")

	user.EXPECT().
		WebAuthnName().
		Return("root@example.com")

	tests := []struct {
		name                  string
		w                     *httptest.ResponseRecorder
		r                     *http.Request
		userStore             func() UserStore
		authSessionStore      func() SessionStore[webauthn.SessionData]
		invalidWebAuthnConfig bool // need this to break webauthn.BeginRegistration()
		wantStatus            int
		checkResp             func(body []byte)
		checkCookie           func(cookies []*http.Cookie)
	}{
		{
			name: "succ: all good",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Create("root@example.com").
					Times(1).
					Return(user, nil)

				return uStore
			},
			authSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Create(mock.AnythingOfType("webauthn.SessionData")).
					Times(1).
					Return("session-token-1234", nil)

				return aStore
			},
			wantStatus: http.StatusOK,
			checkResp: func(body []byte) {
				var resp *protocol.CredentialCreation

				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				r := resp.Response

				assert.NotEmpty(t, r.Challenge)
				assert.Equal(t, "Berik the Cat", r.User.DisplayName)
				assert.Equal(t, "root@example.com", r.User.Name)
			},
			checkCookie: func(cookies []*http.Cookie) {
				assert.Len(t, cookies, 1)
				c := cookies[0]
				assert.Equal(t, camelCaseConcat(defaultSessionNamePrefix, defaultAuthSessionName), c.Name)
				assert.Equal(t, "session-token-1234", c.Value)
				assert.Equal(t, "/", c.Path)
				assert.Equal(t, int(defaultAuthSessionMaxAge.Seconds()), c.MaxAge)
				assert.True(t, c.Secure)
				assert.True(t, c.HttpOnly)
				assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
			},
		},
		{
			name: "err: can't get username",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("foo", "bar")),
			userStore: func() UserStore {
				return NewMockUserStore(t)
			},
			authSessionStore: func() SessionStore[webauthn.SessionData] {
				return NewMockSessionStore[webauthn.SessionData](t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get username: ")
			},
		},
		{
			name: "err: can't create user",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Create("root@example.com").
					Times(1).
					Return(nil, assert.AnError)

				return uStore
			},
			authSessionStore: func() SessionStore[webauthn.SessionData] {
				return NewMockSessionStore[webauthn.SessionData](t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't create user: ")
			},
		},
		{
			name: "err: can't get options from webauthn",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Create("root@example.com").
					Times(1).
					Return(user, nil)

				return uStore
			},
			authSessionStore: func() SessionStore[webauthn.SessionData] {
				return NewMockSessionStore[webauthn.SessionData](t)
			},
			invalidWebAuthnConfig: true,
			wantStatus:            http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't begin registration: ")
			},
		},
		{
			name: "err: can't save session",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Create("root@example.com").
					Times(1).
					Return(user, nil)

				return uStore
			},
			authSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Create(mock.AnythingOfType("webauthn.SessionData")).
					Times(1).
					Return("", assert.AnError)

				return aStore
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't save session: ")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpid := "localhost"
			// to simulate error from `webAuthn.BeginRegistration` make an invalid webauthn config
			if tt.invalidWebAuthnConfig {
				rpid = ""
			}

			p, err := New(
				Config{
					WebauthnConfig: &webauthn.Config{
						RPDisplayName: "Passkey Test",
						RPID:          rpid,
						RPOrigins:     []string{"localhost"},
					},
					UserStore:        tt.userStore(),
					AuthSessionStore: tt.authSessionStore(),
					UserSessionStore: NewMockSessionStore[UserSessionData](t),
				},
			)
			require.NoError(t, err)

			p.beginRegistration(tt.w, tt.r)
			assert.Equal(t, tt.wantStatus, tt.w.Code)

			if tt.checkResp != nil {
				tt.checkResp(tt.w.Body.Bytes())
			}

			if tt.checkCookie != nil {
				tt.checkCookie(tt.w.Result().Cookies())
			}
		})
	}
}

func TestPasskey_finishRegistration(t *testing.T) {
	t.Skip("TODO: implement finishRegistration tests")

	log.Info.Off()
	log.Debg.Off()

	defer func() {
		log.Info.On()
		log.Debg.On()
	}()

	user := NewMockUser(t)
	user.EXPECT().
		WebAuthnID().
		Return([]byte("1234-5678-9012-3456"))

	user.EXPECT().
		WebAuthnDisplayName().
		Return("Berik the Cat")

	user.EXPECT().
		WebAuthnName().
		Return("root@example.com")

	tests := []struct {
		name             string
		w                *httptest.ResponseRecorder
		r                *http.Request
		userStore        func() UserStore
		authSessionStore func() SessionStore[webauthn.SessionData]
		wantStatus       int
		checkResp        func(body []byte)
		checkCookie      func(cookies []*http.Cookie)
	}{
		//{
		//	// TODO: do not forget check cookie
		//	name: "succ: all good",
		//},
		//{
		//	name: "err: can't get session id",
		//},
		//{
		//	name: "err: can't get user",
		//},
		//{
		//	name: "err: can't get credential from webauthn",
		//},
		//{
		//	name: "err: can't save user after putting credential",
		//},
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
					UserStore:        tt.userStore(),
					AuthSessionStore: tt.authSessionStore(),
					UserSessionStore: NewMockSessionStore[UserSessionData](t),
				},
			)
			require.NoError(t, err)

			p.finishRegistration(tt.w, tt.r)
			assert.Equal(t, tt.wantStatus, tt.w.Code)

			if tt.checkResp != nil {
				tt.checkResp(tt.w.Body.Bytes())
			}

			if tt.checkCookie != nil {
				tt.checkCookie(tt.w.Result().Cookies())
			}
		})
	}
}

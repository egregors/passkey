package passkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
	t.Skip("FIXME: handler under development")

	user := NewMockUser(t)
	user.EXPECT().
		WebAuthnID().
		Return([]byte("Berik the Cat"))

	user.EXPECT().
		WebAuthnDisplayName().
		Return("Berik the Cat")

	user.EXPECT().
		WebAuthnName().
		Return("Berik the Cat")

	tests := []struct {
		name         string
		w            *httptest.ResponseRecorder
		r            *http.Request
		repo         func() UserStore
		sessionStore func() SessionStore
		wantStatus   int
		checkResp    func(body []byte)
		checkCookie  func(cookies []*http.Cookie)
	}{
		{
			name: "succ: ok",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "Berik the Cat")),
			repo: func() UserStore {
				store := NewMockRepo(t)
				store.EXPECT().
					GetUserByName("Berik the Cat").
					Times(1).
					Return(user, nil)

				return store
			},
			sessionStore: func() SessionStore {
				store := NewMockSessionStore(t)
				store.EXPECT().
					SaveSession("session-id", mock.AnythingOfType("*webauthn.SessionData")).
					Times(1)

				return store
			},
			wantStatus: http.StatusOK,
			checkCookie: func(cookies []*http.Cookie) {
				assert.Len(t, cookies, 1)
				c := cookies[0]
				assert.Equal(t, "sid", c.Name)
				assert.Equal(t, "session-id", c.Value)
				assert.Equal(t, "/", c.Path)
				assert.Equal(t, 3600, c.MaxAge)
				assert.True(t, c.Secure)
				assert.True(t, c.HttpOnly)
				assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
			},
			checkResp: func(body []byte) {
				var resp *protocol.CredentialCreation

				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				r := resp.Response

				assert.NotEmpty(t, r.Challenge)
				assert.Equal(t, "Berik the Cat", r.User.DisplayName)
				assert.Equal(t, "Berik the Cat", r.User.Name)
			},
		},
		{
			name: "err: can't get username",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("foo", "bar")),
			repo: func() UserStore {
				return NewMockRepo(t)
			},
			sessionStore: func() SessionStore {
				return NewMockSessionStore(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get username: ")
			},
		},
		// FIXME: https://github.com/egregors/passkey/issues/1
		//  real webAuthn.BeginRegistration() call doesn't return an error. It's not possible to test this case.
		//  Probably, we need store User with Registration options. In this case, we can test this case like this:
		//  https://github.com/go-webauthn/webauthn/blob/b5e375ebd23cef3711a8f4dc29a79169f9e8b132/webauthn/registration_test.go#L52

		//{
		//	name: "err: can't begin registration",
		//	w:    httptest.NewRecorder(),
		//	r:    httptest.NewRequest(http.MethodGet, "/", body("username", "Berik the Cat")),
		//	UserStore: func() UserStore {
		//		store := NewMockUserStore(t)
		//		store.EXPECT().
		//			GetOrCreateUser("Berik the Cat").
		//			Times(1).
		//			Return(user, nil)
		//
		//		return store
		//	},
		//	sessionStore: func() SessionStore {
		//		return NewMockSessionStore(t)
		//	},
		//	wantStatus: http.StatusBadRequest,
		// },

		{
			name: "err: can't generate session id",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "Berik the Cat")),
			repo: func() UserStore {
				store := NewMockRepo(t)
				store.EXPECT().
					GetUserByName("Berik the Cat").
					Times(1).
					Return(user, nil)

				return store
			},
			sessionStore: func() SessionStore {
				store := NewMockSessionStore(t)

				return store
			},
			wantStatus: http.StatusInternalServerError,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't generate session id: ")
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
					UserStore:     tt.repo(),
					SessionStore:  tt.sessionStore(),
					SessionMaxAge: 69 * time.Second,
				},
			)
			assert.NoError(t, err)

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

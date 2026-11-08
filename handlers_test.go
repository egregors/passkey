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
	"github.com/stretchr/testify/require"

	"github.com/egregors/passkey/deps"
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
	tests := []struct {
		name                     string
		w                        *httptest.ResponseRecorder
		r                        *http.Request
		userStore                func() UserStore
		registrationSessionStore func() SessionStore[RegistrationSessionData]
		webAuthn                 func() deps.WebAuthnInterface
		wantStatus               int
		checkResp                func(body []byte)
		checkCookie              func(cookies []*http.Cookie)
	}{
		{
			name: "succ: all good",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					GetByName("root@example.com").
					Times(1).
					Return(nil, ErrUserNotFound)

				return uStore
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				rStore := NewMockSessionStore[RegistrationSessionData](t)
				rStore.EXPECT().
					Create(mock.AnythingOfType("passkey.RegistrationSessionData")).
					Times(1).
					Return("session-token-1234", nil)

				return rStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					BeginRegistration(mock.Anything).
					Times(1).
					Return(&protocol.CredentialCreation{}, &webauthn.SessionData{}, nil)

				return wa
			},
			wantStatus: http.StatusOK,
			checkResp: func(body []byte) {
				var resp *protocol.CredentialCreation

				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)
			},
			checkCookie: func(cookies []*http.Cookie) {
				assert.Len(t, cookies, 1)
				c := cookies[0]
				assert.Equal(t, "__Host-"+camelCaseConcat(defaultSessionNamePrefix, defaultRegistrationSessionName), c.Name)
				assert.Equal(t, "session-token-1234", c.Value)
				assert.Equal(t, "/", c.Path)
				assert.Equal(t, int(defaultRegistrationSessionMaxAge.Seconds()), c.MaxAge)
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
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				return NewMockSessionStore[RegistrationSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get username: ")
			},
		},
		{
			name: "err: user already exists",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				existingUser := NewMockUser(t)
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					GetByName("root@example.com").
					Times(1).
					Return(existingUser, nil)

				return uStore
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				return NewMockSessionStore[RegistrationSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "user already exists")
			},
		},
		{
			name: "err: can't get options from webauthn",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					GetByName("root@example.com").
					Times(1).
					Return(nil, ErrUserNotFound)

				return uStore
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				return NewMockSessionStore[RegistrationSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					BeginRegistration(mock.Anything).
					Times(1).
					Return(nil, nil, assert.AnError)

				return wa
			},
			wantStatus: http.StatusBadRequest,
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
					GetByName("root@example.com").
					Times(1).
					Return(nil, ErrUserNotFound)

				return uStore
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				rStore := NewMockSessionStore[RegistrationSessionData](t)
				rStore.EXPECT().
					Create(mock.AnythingOfType("passkey.RegistrationSessionData")).
					Times(1).
					Return("", assert.AnError)

				return rStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					BeginRegistration(mock.Anything).
					Times(1).
					Return(&protocol.CredentialCreation{}, &webauthn.SessionData{}, nil)

				return wa
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't save session: ")
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
					UserStore:                tt.userStore(),
					LoginSessionStore:        NewMockSessionStore[webauthn.SessionData](t),
					RegistrationSessionStore: tt.registrationSessionStore(),
					UserSessionStore:         NewMockSessionStore[UserSessionData](t),
				},
			)
			require.NoError(t, err)
			p.webAuthn = tt.webAuthn()

			limitRequestBody(p.beginRegistration)(tt.w, tt.r)
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
	createdUser := NewMockUser(t)

	tests := []struct {
		name                     string
		w                        *httptest.ResponseRecorder
		r                        func() *http.Request
		userStore                func() UserStore
		registrationSessionStore func() SessionStore[RegistrationSessionData]
		webAuthn                 func() deps.WebAuthnInterface
		wantStatus               int
		checkResp                func(body []byte)
		checkCookie              func(cookies []*http.Cookie)
	}{
		{
			name: "succ: all good",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathRegisterFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultRegistrationSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Create(mock.MatchedBy(func(nu NewUser) bool {
						return nu.Username == "root@example.com" && bytes.Equal(nu.UserID, []byte("1234-5678-9012-3456"))
					})).
					Times(1).
					Return(createdUser, nil)

				return uStore
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				rStore := NewMockSessionStore[RegistrationSessionData](t)
				rStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&RegistrationSessionData{
						Username: "root@example.com",
						Session:  webauthn.SessionData{UserID: []byte("1234-5678-9012-3456")},
						Expires:  time.Now().Add(5 * time.Minute),
					}, true)

				return rStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					FinishRegistration(mock.Anything, mock.AnythingOfType("webauthn.SessionData"), mock.Anything).
					Times(1).
					Return(&webauthn.Credential{}, nil)

				return wa
			},
			wantStatus: http.StatusOK,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "Registration Success")
			},
			checkCookie: func(cookies []*http.Cookie) {
				require.Len(t, cookies, 1)
				c := cookies[0]
				assert.Equal(t, "__Host-"+camelCaseConcat(defaultSessionNamePrefix, defaultRegistrationSessionName), c.Name)
				assert.Empty(t, c.Value)
				assert.Equal(t, -1, c.MaxAge)
			},
		},
		{
			name: "err: can't get session id from cookie",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				// request without session cookie
				return httptest.NewRequest(http.MethodPost, pathRegisterFinish, http.NoBody)
			},
			userStore: func() UserStore {
				return NewMockUserStore(t)
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				return NewMockSessionStore[RegistrationSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get session id: ")
			},
		},
		{
			name: "err: can't get session data",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathRegisterFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultRegistrationSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				return NewMockUserStore(t)
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				rStore := NewMockSessionStore[RegistrationSessionData](t)
				rStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(nil, false)

				return rStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get session data")
			},
		},
		{
			name: "err: session expired",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathRegisterFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultRegistrationSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				return NewMockUserStore(t)
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				rStore := NewMockSessionStore[RegistrationSessionData](t)
				rStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&RegistrationSessionData{
						Username: "root@example.com",
						Session:  webauthn.SessionData{UserID: []byte("1234-5678-9012-3456")},
						Expires:  time.Now().Add(-1 * time.Minute), // expired
					}, true)

				return rStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "registration session has expired")
			},
		},
		{
			name: "err: can't get credential from webauthn",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathRegisterFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultRegistrationSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				return NewMockUserStore(t)
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				rStore := NewMockSessionStore[RegistrationSessionData](t)
				rStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&RegistrationSessionData{
						Username: "root@example.com",
						Session:  webauthn.SessionData{UserID: []byte("1234-5678-9012-3456")},
						Expires:  time.Now().Add(5 * time.Minute),
					}, true)

				return rStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					FinishRegistration(mock.Anything, mock.AnythingOfType("webauthn.SessionData"), mock.Anything).
					Times(1).
					Return(nil, assert.AnError)

				return wa
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't finish registration: ")
			},
		},
		{
			name: "err: can't create user",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathRegisterFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultRegistrationSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Create(mock.Anything).
					Times(1).
					Return(nil, assert.AnError)

				return uStore
			},
			registrationSessionStore: func() SessionStore[RegistrationSessionData] {
				rStore := NewMockSessionStore[RegistrationSessionData](t)
				rStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&RegistrationSessionData{
						Username: "root@example.com",
						Session:  webauthn.SessionData{UserID: []byte("1234-5678-9012-3456")},
						Expires:  time.Now().Add(5 * time.Minute),
					}, true)

				return rStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					FinishRegistration(mock.Anything, mock.AnythingOfType("webauthn.SessionData"), mock.Anything).
					Times(1).
					Return(&webauthn.Credential{}, nil)

				return wa
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't create user: ")
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
					UserStore:                tt.userStore(),
					LoginSessionStore:        NewMockSessionStore[webauthn.SessionData](t),
					RegistrationSessionStore: tt.registrationSessionStore(),
					UserSessionStore:         NewMockSessionStore[UserSessionData](t),
				},
			)
			require.NoError(t, err)
			p.webAuthn = tt.webAuthn()

			limitRequestBody(p.finishRegistration)(tt.w, tt.r())
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

func TestPasskey_beginLogin(t *testing.T) {
	user := NewMockUser(t)

	user.EXPECT().
		WebAuthnName().
		Return("root@example.com")

	tests := []struct {
		name              string
		w                 *httptest.ResponseRecorder
		r                 *http.Request
		userStore         func() UserStore
		loginSessionStore func() SessionStore[webauthn.SessionData]
		webAuthn          func() deps.WebAuthnInterface
		wantStatus        int
		checkResp         func(body []byte)
		checkCookie       func(cookies []*http.Cookie)
	}{
		{
			name: "succ: all good",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					GetByName("root@example.com").
					Times(1).
					Return(user, nil)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Create(mock.AnythingOfType("webauthn.SessionData")).
					Times(1).
					Return("session-token-1234", nil)

				return aStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					BeginLogin(user).
					Times(1).
					Return(&protocol.CredentialAssertion{}, &webauthn.SessionData{}, nil)

				return wa
			},
			wantStatus: http.StatusOK,
			checkResp: func(body []byte) {
			},
			checkCookie: func(cookies []*http.Cookie) {
				assert.Len(t, cookies, 1)
				c := cookies[0]
				assert.Equal(t, "__Host-"+camelCaseConcat(defaultSessionNamePrefix, defaultLoginSessionName), c.Name)
				assert.Equal(t, "session-token-1234", c.Value)
				assert.Equal(t, "/", c.Path)
				assert.Equal(t, int(defaultLoginSessionMaxAge.Seconds()), c.MaxAge)
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
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				return NewMockSessionStore[webauthn.SessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get username: ")
			},
		},
		{
			name: "err: can't get user",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					GetByName("root@example.com").
					Times(1).
					Return(nil, assert.AnError)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				return NewMockSessionStore[webauthn.SessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get user: ")
			},
		},
		{
			name: "err: can't get options from webauthn",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					GetByName("root@example.com").
					Times(1).
					Return(user, nil)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				return NewMockSessionStore[webauthn.SessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					BeginLogin(user).
					Times(1).
					Return(nil, nil, assert.AnError)

				return wa
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't begin login: ")
			},
		},
		{
			name: "err: can't save session",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodGet, "/", body("username", "root@example.com")),
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					GetByName("root@example.com").
					Times(1).
					Return(user, nil)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Create(mock.AnythingOfType("webauthn.SessionData")).
					Times(1).
					Return("", assert.AnError)

				return aStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					BeginLogin(user).
					Times(1).
					Return(&protocol.CredentialAssertion{}, &webauthn.SessionData{}, nil)

				return wa
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't save session: ")
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
					UserStore:                tt.userStore(),
					LoginSessionStore:        tt.loginSessionStore(),
					RegistrationSessionStore: NewMockSessionStore[RegistrationSessionData](t),
					UserSessionStore:         NewMockSessionStore[UserSessionData](t),
				},
			)
			require.NoError(t, err)
			p.webAuthn = tt.webAuthn()

			limitRequestBody(p.beginLogin)(tt.w, tt.r)
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

func TestPasskey_deleteSessionCookie(t *testing.T) {
	t.Parallel()

	p := &Passkey{}
	p.setupCookieSettings()
	w := httptest.NewRecorder()

	p.deleteSessionCookie(p.cookieSettings.userSessionName, w)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, p.cookieSettings.userSessionName, cookie.Name)
	assert.Equal(t, p.cookieSettings.Path, cookie.Path)
	assert.Equal(t, -1, cookie.MaxAge)
	assert.True(t, cookie.Secure)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
}

func TestPasskey_finishLogin(t *testing.T) {
	user := NewMockUser(t)
	user.EXPECT().
		WebAuthnName().
		Return("root@example.com")

	tests := []struct {
		name              string
		w                 *httptest.ResponseRecorder
		r                 func() *http.Request
		userStore         func() UserStore
		loginSessionStore func() SessionStore[webauthn.SessionData]
		userSessionStore  func() SessionStore[UserSessionData]
		webAuthn          func() deps.WebAuthnInterface
		wantStatus        int
		checkResp         func(body []byte)
	}{
		{
			name: "succ: all good",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathLoginFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultLoginSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Get([]byte("1234-5678-9012-3456")).
					Times(1).
					Return(user, nil)
				uStore.EXPECT().
					UpdateCredential([]byte("1234-5678-9012-3456"), mock.AnythingOfType("webauthn.Credential")).
					Times(1).
					Return(nil)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&webauthn.SessionData{UserID: []byte("1234-5678-9012-3456"), Expires: time.Now().Add(5 * time.Minute)}, true)

				return aStore
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				uStore := NewMockSessionStore[UserSessionData](t)
				uStore.EXPECT().
					Create(mock.AnythingOfType("UserSessionData")).
					Times(1).
					Return("user-session-token-1234", nil)

				return uStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					FinishLogin(user, mock.AnythingOfType("webauthn.SessionData"), mock.Anything).
					Times(1).
					Return(&webauthn.Credential{}, nil)

				return wa
			},
			wantStatus: http.StatusOK,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "Login Success")
			},
		},
		{
			name: "err: can't get session id from cookie",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				// request without session cookie
				return httptest.NewRequest(http.MethodPost, pathLoginFinish, http.NoBody)
			},
			userStore: func() UserStore {
				return NewMockUserStore(t)
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				return NewMockSessionStore[webauthn.SessionData](t)
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				return NewMockSessionStore[UserSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get session id: ")
			},
		},
		{
			name: "err: can't get session data",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathLoginFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultLoginSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				return NewMockUserStore(t)
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(nil, false)

				return aStore
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				return NewMockSessionStore[UserSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get session data")
			},
		},
		{
			name: "err: can't get user",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathLoginFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultLoginSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Get([]byte("1234-5678-9012-3456")).
					Times(1).
					Return(nil, assert.AnError)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&webauthn.SessionData{UserID: []byte("1234-5678-9012-3456"), Expires: time.Now().Add(5 * time.Minute)}, true)

				return aStore
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				return NewMockSessionStore[UserSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				return deps.NewMockWebAuthnInterface(t)
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't get user: ")
			},
		},
		{
			name: "err: can't get credential from webauthn",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathLoginFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultLoginSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Get([]byte("1234-5678-9012-3456")).
					Times(1).
					Return(user, nil)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&webauthn.SessionData{UserID: []byte("1234-5678-9012-3456"), Expires: time.Now().Add(5 * time.Minute)}, true)

				return aStore
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				return NewMockSessionStore[UserSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					FinishLogin(user, mock.AnythingOfType("webauthn.SessionData"), mock.Anything).
					Times(1).
					Return(nil, assert.AnError)

				return wa
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't finish login: ")
			},
		},
		{
			name: "err: credential update failed",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathLoginFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultLoginSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Get([]byte("1234-5678-9012-3456")).
					Times(1).
					Return(user, nil)
				uStore.EXPECT().
					UpdateCredential([]byte("1234-5678-9012-3456"), mock.AnythingOfType("webauthn.Credential")).
					Times(1).
					Return(assert.AnError)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&webauthn.SessionData{UserID: []byte("1234-5678-9012-3456"), Expires: time.Now().Add(5 * time.Minute)}, true)

				return aStore
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				return NewMockSessionStore[UserSessionData](t)
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					FinishLogin(user, mock.AnythingOfType("webauthn.SessionData"), mock.Anything).
					Times(1).
					Return(&webauthn.Credential{}, nil)

				return wa
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't update credential: ")
			},
		},
		{
			name: "err: can't save user session",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, pathLoginFinish, http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultLoginSessionName),
					Value: "session-token-1234",
				})

				return req
			},
			userStore: func() UserStore {
				uStore := NewMockUserStore(t)
				uStore.EXPECT().
					Get([]byte("1234-5678-9012-3456")).
					Times(1).
					Return(user, nil)
				uStore.EXPECT().
					UpdateCredential([]byte("1234-5678-9012-3456"), mock.AnythingOfType("webauthn.Credential")).
					Times(1).
					Return(nil)

				return uStore
			},
			loginSessionStore: func() SessionStore[webauthn.SessionData] {
				aStore := NewMockSessionStore[webauthn.SessionData](t)
				aStore.EXPECT().
					Consume("session-token-1234").
					Times(1).
					Return(&webauthn.SessionData{UserID: []byte("1234-5678-9012-3456"), Expires: time.Now().Add(5 * time.Minute)}, true)

				return aStore
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				uStore := NewMockSessionStore[UserSessionData](t)
				uStore.EXPECT().
					Create(mock.AnythingOfType("UserSessionData")).
					Times(1).
					Return("", assert.AnError)

				return uStore
			},
			webAuthn: func() deps.WebAuthnInterface {
				wa := deps.NewMockWebAuthnInterface(t)
				wa.EXPECT().
					FinishLogin(user, mock.AnythingOfType("webauthn.SessionData"), mock.Anything).
					Times(1).
					Return(&webauthn.Credential{}, nil)

				return wa
			},
			wantStatus: http.StatusBadRequest,
			checkResp: func(body []byte) {
				assert.Contains(t, string(body), "can't save user session: ")
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
					UserStore:                tt.userStore(),
					LoginSessionStore:        tt.loginSessionStore(),
					RegistrationSessionStore: NewMockSessionStore[RegistrationSessionData](t),
					UserSessionStore:         tt.userSessionStore(),
				},
			)
			require.NoError(t, err)
			p.webAuthn = tt.webAuthn()

			req := tt.r()
			limitRequestBody(p.finishLogin)(tt.w, req)
			assert.Equal(t, tt.wantStatus, tt.w.Code)
			if _, cookieErr := req.Cookie(p.cookieSettings.loginSessionName); cookieErr == nil {
				assertLoginCookieCleared(t, p, tt.w)
			} else {
				assert.Empty(t, tt.w.Result().Cookies())
			}

			if tt.checkResp != nil {
				tt.checkResp(tt.w.Body.Bytes())
			}
		})
	}
}

func TestPasskey_Logout(t *testing.T) {
	tests := []struct {
		name             string
		w                *httptest.ResponseRecorder
		r                func() *http.Request
		userSessionStore func() SessionStore[UserSessionData]
		checkCookie      func(cookies []*http.Cookie)
	}{
		{
			name: "succ: logout deletes session and cookie",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/logout", http.NoBody)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-" + camelCaseConcat(defaultSessionNamePrefix, defaultUserSessionName),
					Value: "user-session-token-1234",
				})

				return req
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				uStore := NewMockSessionStore[UserSessionData](t)
				uStore.EXPECT().
					Delete("user-session-token-1234").
					Times(1)
				return uStore
			},
			checkCookie: func(cookies []*http.Cookie) {
				require.Len(t, cookies, 1)
				c := cookies[0]
				assert.Equal(t, "__Host-"+camelCaseConcat(defaultSessionNamePrefix, defaultUserSessionName), c.Name)
				assert.Empty(t, c.Value)
				assert.Equal(t, -1, c.MaxAge)
			},
		},
		{
			name: "err: no cookie",
			w:    httptest.NewRecorder(),
			r: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/logout", http.NoBody)
			},
			userSessionStore: func() SessionStore[UserSessionData] {
				return NewMockSessionStore[UserSessionData](t)
			},
			checkCookie: func(cookies []*http.Cookie) {
				assert.Empty(t, cookies)
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
					UserStore:                NewMockUserStore(t),
					LoginSessionStore:        NewMockSessionStore[webauthn.SessionData](t),
					RegistrationSessionStore: NewMockSessionStore[RegistrationSessionData](t),
					UserSessionStore:         tt.userSessionStore(),
				},
			)
			require.NoError(t, err)

			req := tt.r()
			req.Header.Set("Origin", "localhost")
			p.Logout(tt.w, req)
			assert.Equal(t, http.StatusNoContent, tt.w.Code)

			if tt.checkCookie != nil {
				tt.checkCookie(tt.w.Result().Cookies())
			}
		})
	}
}

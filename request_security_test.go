package passkey

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/egregors/passkey/deps"
)

func withAllowedOrigin(r *http.Request) *http.Request {
	r.Header.Set("Origin", "https://example.com")
	return r
}

func securityPasskey(t *testing.T, opts ...Option) *Passkey {
	t.Helper()
	p, err := New(Config{
		WebauthnConfig: &webauthn.Config{RPID: "example.com", RPDisplayName: "test", RPOrigins: []string{"https://example.com"}},
		UserStore:      NewMockUserStore(t), LoginSessionStore: NewMockSessionStore[webauthn.SessionData](t),
		RegistrationSessionStore: NewMockSessionStore[RegistrationSessionData](t),
		UserSessionStore:         NewMockSessionStore[UserSessionData](t),
	}, opts...)
	require.NoError(t, err)
	p.webAuthn = deps.NewMockWebAuthnInterface(t)
	return p
}

func TestMutationRequestsRejectedWithoutSideEffects(t *testing.T) {
	for _, path := range []string{pathRegisterBegin, pathRegisterFinish, pathLoginBegin, pathLoginFinish, "/logout"} {
		for _, tt := range []struct {
			name, method string
			origins      []string
			status       int
		}{
			{"GET", http.MethodGet, []string{"https://example.com"}, http.StatusMethodNotAllowed},
			{"HEAD", http.MethodHead, []string{"https://example.com"}, http.StatusMethodNotAllowed},
			{"PUT", http.MethodPut, []string{"https://example.com"}, http.StatusMethodNotAllowed},
			{"OPTIONS", http.MethodOptions, []string{"https://example.com"}, http.StatusMethodNotAllowed},
			{"missing origin", http.MethodPost, nil, http.StatusForbidden},
			{"empty origin", http.MethodPost, []string{""}, http.StatusForbidden},
			{"null origin", http.MethodPost, []string{"null"}, http.StatusForbidden},
			{"foreign origin", http.MethodPost, []string{"https://evil.example"}, http.StatusForbidden},
			{"sibling origin", http.MethodPost, []string{"https://untrusted.example.com"}, http.StatusForbidden},
			{"HTTP origin", http.MethodPost, []string{"http://example.com"}, http.StatusForbidden},
			{"other port", http.MethodPost, []string{"https://example.com:8443"}, http.StatusForbidden},
			{"duplicate origin", http.MethodPost, []string{"https://example.com", "https://example.com"}, http.StatusForbidden},
			{"origin list", http.MethodPost, []string{"https://example.com https://evil.example"}, http.StatusForbidden},
		} {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				p := securityPasskey(t)
				body := &trackedRequestBody{Reader: strings.NewReader(`{}`)}
				req := httptest.NewRequest(tt.method, path, http.NoBody)
				req.Body = body
				req.Header["Origin"] = tt.origins
				for _, name := range []string{p.cookieSettings.loginSessionName, p.cookieSettings.registrationSessionName, p.cookieSettings.userSessionName} {
					req.AddCookie(&http.Cookie{Name: name, Value: "token"})
				}
				rec := httptest.NewRecorder()
				if path == "/logout" {
					p.Logout(rec, req)
				} else {
					p.mux.ServeHTTP(rec, req)
				}
				assert.Equal(t, tt.status, rec.Code)
				if tt.status == http.StatusMethodNotAllowed {
					assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
				}
				assert.Zero(t, body.bytesRead)
				assert.Empty(t, rec.Result().Cookies())
			})
		}
	}
}

func TestDuplicateSessionCookiesRejected(t *testing.T) {
	for _, path := range []string{pathRegisterFinish, pathLoginFinish, "/logout", "/private"} {
		for _, separateHeaders := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/one header", true: "/two headers"}[separateHeaders], func(t *testing.T) {
				p := securityPasskey(t)
				name := p.cookieSettings.userSessionName
				switch path {
				case pathRegisterFinish:
					name = p.cookieSettings.registrationSessionName
				case pathLoginFinish:
					name = p.cookieSettings.loginSessionName
				}
				req := withAllowedOrigin(httptest.NewRequest(http.MethodPost, path, http.NoBody))
				if separateHeaders {
					req.Header.Add("Cookie", name+"=attacker")
					req.Header.Add("Cookie", name+"=victim")
				} else {
					req.Header.Set("Cookie", name+"=attacker; other=ok; "+name+"=victim")
				}
				rec := httptest.NewRecorder()
				wantStatus := http.StatusBadRequest
				switch path {
				case "/private":
					wantStatus = http.StatusUnauthorized
					called := false
					p.Auth("user", func(http.ResponseWriter, *http.Request) { called = true }, Unauthorized)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
						called = true
					})).ServeHTTP(rec, req)
					assert.False(t, called)
				case "/logout":
					p.Logout(rec, req)
				default:
					p.mux.ServeHTTP(rec, req)
				}
				assert.Equal(t, wantStatus, rec.Code)
				assert.Empty(t, rec.Result().Cookies())
			})
		}
	}
}

func TestCookieScopeAndOptionOrder(t *testing.T) {
	for _, tt := range []struct {
		name   string
		opts   []Option
		secure bool
		prefix string
	}{
		{"production", nil, true, "__Host-pk"},
		{"custom", []Option{WithSessionCookieNamePrefix("Demo")}, true, "__Host-demo"},
		{"local first", []Option{WithInsecureCookie(), WithSessionCookieNamePrefix("Demo")}, false, "demo"},
		{"local last", []Option{WithSessionCookieNamePrefix("Demo"), WithInsecureCookie()}, false, "demo"},
		{"last prefix wins", []Option{WithSessionCookieNamePrefix("First"), WithSessionCookieNamePrefix("Demo")}, true, "__Host-demo"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := securityPasskey(t, tt.opts...)
			assert.Equal(t, tt.prefix+"Lsid", p.cookieSettings.loginSessionName)
			assert.Equal(t, tt.prefix+"Rsid", p.cookieSettings.registrationSessionName)
			assert.Equal(t, tt.prefix+"Usid", p.cookieSettings.userSessionName)
			for _, set := range []func(http.ResponseWriter, string){p.setLoginSessionCookie, p.setRegistrationSessionCookie, p.setUserSessionCookie} {
				rec := httptest.NewRecorder()
				set(rec, "token")
				cookies := rec.Result().Cookies()
				require.Len(t, cookies, 1)
				for _, deleting := range []bool{false, true} {
					cookie := cookies[0]
					if deleting {
						rec = httptest.NewRecorder()
						p.deleteSessionCookie(cookie.Name, rec)
						cookie = rec.Result().Cookies()[0]
						assert.Equal(t, -1, cookie.MaxAge)
					}
					assert.Equal(t, tt.secure, cookie.Secure)
					assert.Equal(t, "/", cookie.Path)
					assert.Empty(t, cookie.Domain)
					assert.True(t, cookie.HttpOnly)
					assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
				}
			}
		})
	}
}

func TestReservedPrefixesRequireSecureCookies(t *testing.T) {
	for _, prefix := range []string{"__Host-demo", "__Secure-demo"} {
		for _, opts := range [][]Option{
			{WithInsecureCookie(), WithSessionCookieNamePrefix(prefix)},
			{WithSessionCookieNamePrefix(prefix), WithInsecureCookie()},
		} {
			_, err := New(securityPasskey(t).cfg, opts...)
			require.Error(t, err)
		}
	}
}

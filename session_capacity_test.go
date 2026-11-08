package passkey

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBeginAdmissionMiddleware(t *testing.T) {
	for _, path := range []string{pathRegisterBegin, pathLoginBegin} {
		t.Run(path, func(t *testing.T) {
			f := newLoginReplayFixture(t)
			if path == pathLoginBegin {
				f.users.On("GetByName", "user").Return(f.user, nil).Once()
			} else {
				f.users.On("GetByName", "user").Return(nil, ErrUserNotFound).Once()
				f.p.registrationSessionStore = &loginReplayStore[RegistrationSessionData]{data: make(map[string]RegistrationSessionData)}
			}
			api := http.NewServeMux()
			f.p.MountRoutes(api, "/api/")
			remaining := 1
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if remaining == 0 {
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				remaining--
				api.ServeHTTP(w, r)
			})
			for _, status := range []int{http.StatusOK, http.StatusTooManyRequests} {
				req := httptest.NewRequest(http.MethodPost, "/api"+path, body("username", "user"))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				assert.Equal(t, status, rec.Code)
				if status == http.StatusTooManyRequests {
					assert.Empty(t, rec.Result().Cookies())
				}
			}
		})
	}
}

func TestLoginUserSessionCapacity(t *testing.T) {
	f := newLoginReplayFixture(t)
	f.users.On("Get", f.userID).Return(f.user, nil).Once()
	f.users.On("UpdateCredential", f.userID, mock.AnythingOfType("webauthn.Credential")).Return(nil).Once()
	f.authSessions.createErr = fmt.Errorf("private backend detail: %w", ErrSessionStoreFull)
	rec := f.finish(f.assertion)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.JSONEq(t, `"session storage is full"`, rec.Body.String())
	assertLoginCookieCleared(t, f.p, rec)
	assert.Zero(t, f.authSessions.count())
	for _, cookie := range rec.Result().Cookies() {
		assert.NotEqual(t, f.p.cookieSettings.userSessionName, cookie.Name)
	}
}

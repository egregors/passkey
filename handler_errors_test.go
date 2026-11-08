package passkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/egregors/passkey/deps"
)

func TestBeginBackendErrorsArePrivate(t *testing.T) {
	var value any
	parseErr := json.Unmarshal([]byte("invalid"), &value)
	require.Error(t, parseErr)
	for _, path := range []string{pathRegisterBegin, pathLoginBegin} {
		for _, cause := range []error{errors.New("driver failure"), parseErr, protocol.ErrBadRequest.WithDetails("backend validation failure")} {
			t.Run(path+"/"+fmt.Sprintf("%T", cause), func(t *testing.T) {
				p := securityPasskey(t)
				p.userStore.(*MockUserStore).On("GetByName", "user").Return(nil, fmt.Errorf("private backend diagnostic: %w", cause)).Once()
				rec := httptest.NewRecorder()
				p.mux.ServeHTTP(rec, withAllowedOrigin(httptest.NewRequest(http.MethodPost, path, body("username", "user"))))
				assert.Equal(t, http.StatusInternalServerError, rec.Code)
				assert.JSONEq(t, `"internal server error"`, rec.Body.String())
				assert.Empty(t, rec.Result().Cookies())
			})
		}
	}
}

func TestMalformedRequestIsClientError(t *testing.T) {
	for _, path := range []string{pathRegisterBegin, pathLoginBegin} {
		t.Run(path, func(t *testing.T) {
			p := securityPasskey(t)
			rec := httptest.NewRecorder()
			p.mux.ServeHTTP(rec, withAllowedOrigin(httptest.NewRequest(http.MethodPost, path, strings.NewReader("invalid"))))
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.JSONEq(t, `"invalid request"`, rec.Body.String())
			assert.Empty(t, rec.Result().Cookies())
		})
	}
}

func TestMissingRecordsHavePublicResponses(t *testing.T) {
	for _, stage := range []string{"begin lookup", "finish lookup", "credential update"} {
		t.Run(stage, func(t *testing.T) {
			f := newLoginReplayFixture(t)
			cause := ErrUserNotFound
			if stage == "credential update" {
				cause = ErrCredentialNotFound
			}
			backendErr := fmt.Errorf("private backend diagnostic: %w", cause)
			var rec *httptest.ResponseRecorder
			switch stage {
			case "begin lookup":
				f.users.On("GetByName", "missing").Return(nil, backendErr).Once()
				rec = httptest.NewRecorder()
				f.p.mux.ServeHTTP(rec, withAllowedOrigin(httptest.NewRequest(http.MethodPost, pathLoginBegin, body("username", "missing"))))
			case "finish lookup":
				f.users.On("Get", f.userID).Return(nil, backendErr).Once()
				rec = f.finish(f.assertion)
			default:
				f.users.On("Get", f.userID).Return(f.user, nil).Once()
				f.users.On("UpdateCredential", f.userID, mock.Anything).Return(backendErr).Once()
				rec = f.finish(f.assertion)
			}
			assert.Equal(t, http.StatusNotFound, rec.Code)
			assert.JSONEq(t, fmt.Sprintf("%q", cause.Error()), rec.Body.String())
			assert.Zero(t, f.authSessions.count())
		})
	}
}

func TestVerificationErrorResponses(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{"invalid signature", protocol.ErrAssertionSignature.WithDetails("private verification detail"), 400, "invalid request"},
		{"metadata failure", protocol.ErrMetadata.WithDetails("private metadata detail"), 500, "internal server error"},
		{"unknown protocol failure", &protocol.Error{Type: "unknown", Details: "private detail"}, 500, "internal server error"},
		{"unexpected failure", errors.New("private implementation detail"), 500, "internal server error"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newLoginReplayFixture(t)
			f.users.On("Get", f.userID).Return(f.user, nil).Once()
			wa := deps.NewMockWebAuthnInterface(t)
			wa.On("FinishLogin", f.user, mock.Anything, mock.Anything).Return(nil, tt.err).Once()
			f.p.webAuthn = wa
			rec := f.finish(f.assertion)
			assert.Equal(t, tt.status, rec.Code)
			assert.JSONEq(t, fmt.Sprintf("%q", tt.message), rec.Body.String())
			assertLoginCookieCleared(t, f.p, rec)
			assert.Zero(t, f.authSessions.count())
		})
	}
}

func TestInvalidRegistrationResponseIsClientError(t *testing.T) {
	f := newLoginReplayFixture(t)
	store := &loginReplayStore[RegistrationSessionData]{data: make(map[string]RegistrationSessionData)}
	f.p.registrationSessionStore = store
	token, err := store.Create(RegistrationSessionData{
		Username: "user", Session: webauthn.SessionData{UserID: []byte("user")}, Expires: time.Now().Add(time.Minute),
	})
	require.NoError(t, err)
	req := withAllowedOrigin(httptest.NewRequest(http.MethodPost, pathRegisterFinish, strings.NewReader(`{}`)))
	req.AddCookie(&http.Cookie{Name: f.p.cookieSettings.registrationSessionName, Value: token})
	rec := httptest.NewRecorder()
	f.p.mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.JSONEq(t, `"invalid request"`, rec.Body.String())
	assert.Zero(t, store.count())
	assert.Zero(t, f.authSessions.count())
}

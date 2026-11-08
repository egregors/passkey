package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/egregors/passkey"
)

func TestSessionStoreExpiration(t *testing.T) {
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)
	t.Run("login", func(t *testing.T) {
		checkSessionExpiration(t, webauthn.SessionData{Expires: future}, webauthn.SessionData{Expires: past})
	})
	t.Run("registration", func(t *testing.T) {
		checkSessionExpiration(t, passkey.RegistrationSessionData{Expires: future}, passkey.RegistrationSessionData{Expires: past})
	})
	t.Run("user", func(t *testing.T) {
		checkSessionExpiration(t, passkey.UserSessionData{Expires: future}, passkey.UserSessionData{Expires: past})
	})
}

func checkSessionExpiration[T any](t *testing.T, valid, expired T) {
	t.Helper()
	s := NewSessionStore[T]()
	_, err := s.Create(expired)
	require.Error(t, err)
	var zero T
	_, err = s.Create(zero)
	require.Error(t, err)
	token, err := s.Create(valid)
	require.NoError(t, err)
	got, ok := s.Get(token)
	require.True(t, ok)
	assert.Equal(t, valid, *got)
	got, ok = s.Consume(token)
	require.True(t, ok)
	assert.Equal(t, valid, *got)
	_, ok = s.Consume(token)
	assert.False(t, ok)
	for _, consume := range []bool{false, true} {
		s.sessions["expired"] = expired
		if consume {
			_, ok = s.Consume("expired")
		} else {
			_, ok = s.Get("expired")
		}
		assert.False(t, ok)
		assert.Empty(t, s.sessions)
	}
	token, err = s.Create(valid)
	require.NoError(t, err)
	s.Delete(token)
	_, ok = s.Get(token)
	assert.False(t, ok)
}

func TestSessionStoreCapacityAndEviction(t *testing.T) {
	s := NewSessionStore[webauthn.SessionData]()
	valid := webauthn.SessionData{Expires: time.Now().Add(time.Hour)}
	for i := range sessionStoreCapacity - 1 {
		s.sessions[fmt.Sprint(i)] = valid
	}
	errors := make(chan error, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { _, err := s.Create(valid); errors <- err })
	}
	wg.Wait()
	close(errors)
	successes := 0
	for err := range errors {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, passkey.ErrSessionStoreFull)
		}
	}
	assert.Equal(t, 1, successes)
	require.Len(t, s.sessions, sessionStoreCapacity)
	s.sessions["0"] = webauthn.SessionData{Expires: time.Now().Add(-time.Hour)}
	_, err := s.Create(valid)
	require.NoError(t, err)
	assert.Len(t, s.sessions, sessionStoreCapacity)
	_, exists := s.sessions["0"]
	assert.False(t, exists)
}

func TestCookieLessBeginRequestsAreBounded(t *testing.T) {
	for _, path := range []string{"/passkey/registerBegin", "/passkey/loginBegin"} {
		t.Run(path, func(t *testing.T) {
			users := NewUserStore()
			if path == "/passkey/loginBegin" {
				_, err := users.Create(passkey.NewUser{Username: "user", UserID: []byte("user"), Credential: testCredential()})
				require.NoError(t, err)
			}
			login := NewSessionStore[webauthn.SessionData]()
			registration := NewSessionStore[passkey.RegistrationSessionData]()
			p, err := passkey.New(passkey.Config{
				WebauthnConfig: &webauthn.Config{RPID: "example.com", RPDisplayName: "test", RPOrigins: []string{"https://example.com"}},
				UserStore:      users, LoginSessionStore: login, RegistrationSessionStore: registration,
				UserSessionStore: NewSessionStore[passkey.UserSessionData](),
			})
			require.NoError(t, err)
			mux := http.NewServeMux()
			p.MountRoutes(mux, "/api/")
			for i := range sessionStoreCapacity + 2 {
				req := httptest.NewRequest(http.MethodPost, "/api"+path, strings.NewReader(`{"username":"user"}`))
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if i < sessionStoreCapacity {
					require.Equal(t, http.StatusOK, rec.Code)
				} else {
					assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
					assert.JSONEq(t, `"session storage is full"`, rec.Body.String())
					assert.Empty(t, rec.Result().Cookies())
				}
			}
			if path == "/passkey/loginBegin" {
				assert.Len(t, login.sessions, sessionStoreCapacity)
			} else {
				assert.Len(t, registration.sessions, sessionStoreCapacity)
			}
		})
	}
}

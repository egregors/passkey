package passkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestLoginConcurrentReplay(t *testing.T) {
	f := newLoginReplayFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var lookups atomic.Int32
	f.users.On("Get", f.userID).Run(func(mock.Arguments) {
		if lookups.Add(1) == 1 {
			close(entered)
			<-release
		}
	}).Return(f.user, nil)
	f.users.On("Update", f.user).Return(nil)

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- f.finish(f.assertion) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not reach user lookup")
	}

	// The first request is still in flight. A Get-then-Delete implementation
	// would let this identical signed response complete another login.
	second := f.finish(f.assertion)
	assert.Equal(t, http.StatusBadRequest, second.Code)
	assert.Contains(t, second.Body.String(), "can't get session data")
	assertLoginCookieCleared(t, f.p, second)
	unblock()
	select {
	case rec := <-first:
		assert.Equal(t, http.StatusOK, rec.Code)
		assertLoginCookieCleared(t, f.p, rec)
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not finish")
	}
	assert.Equal(t, 1, f.authSessions.count())
	f.users.AssertNumberOfCalls(t, "Get", 1)
	f.users.AssertNumberOfCalls(t, "Update", 1)
	f.user.AssertNumberOfCalls(t, "PutCredential", 1)
}

func TestLoginSequentialReplay(t *testing.T) {
	f := newLoginReplayFixture(t)
	f.users.On("Get", f.userID).Return(f.user, nil).Once()
	f.users.On("Update", f.user).Return(nil).Once()
	first := f.finish(f.assertion)
	assert.Equal(t, http.StatusOK, first.Code)
	assertLoginCookieCleared(t, f.p, first)
	second := f.finish(f.assertion)
	assert.Equal(t, http.StatusBadRequest, second.Code)
	assert.Contains(t, second.Body.String(), "can't get session data")
	assertLoginCookieCleared(t, f.p, second)
	assert.Equal(t, 1, f.authSessions.count())
}

func TestLoginInvalidSignatureConsumesChallenge(t *testing.T) {
	f := newLoginReplayFixture(t)
	f.users.On("Get", f.userID).Return(f.user, nil).Once()
	first := f.finish(f.invalidAssertion)
	assert.Equal(t, http.StatusBadRequest, first.Code)
	assert.Contains(t, first.Body.String(), "can't finish login")
	assertLoginCookieCleared(t, f.p, first)
	// Even a valid signature cannot retry this ceremony after the failed attempt.
	second := f.finish(f.assertion)
	assert.Equal(t, http.StatusBadRequest, second.Code)
	assert.Contains(t, second.Body.String(), "can't get session data")
	assertLoginCookieCleared(t, f.p, second)
	assert.Zero(t, f.authSessions.count())
}

func TestLoginStorageFailureConsumesChallenge(t *testing.T) {
	for _, stage := range []string{"load user", "update user", "create session"} {
		t.Run(stage, func(t *testing.T) {
			f := newLoginReplayFixture(t)
			if stage == "load user" {
				f.users.On("Get", f.userID).Return(nil, assert.AnError).Once()
			} else {
				f.users.On("Get", f.userID).Return(f.user, nil).Once()
				var updateErr error
				if stage == "update user" {
					updateErr = assert.AnError
				} else {
					f.authSessions.createErr = assert.AnError
				}
				f.users.On("Update", f.user).Return(updateErr).Once()
			}
			first := f.finish(f.assertion)
			assert.Equal(t, http.StatusBadRequest, first.Code)
			assertLoginCookieCleared(t, f.p, first)
			second := f.finish(f.assertion)
			assert.Equal(t, http.StatusBadRequest, second.Code)
			assert.Contains(t, second.Body.String(), "can't get session data")
			assertLoginCookieCleared(t, f.p, second)
			assert.Zero(t, f.authSessions.count())
		})
	}
}

func TestLoginNilConsumedSession(t *testing.T) {
	f := newLoginReplayFixture(t)
	store := NewMockSessionStore[webauthn.SessionData](t)
	store.On("Consume", f.token).Return(nil, true).Once()
	f.p.loginSessionStore = store
	rec := f.finish(f.assertion)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "can't get session data")
	assertLoginCookieCleared(t, f.p, rec)
	assert.Zero(t, f.authSessions.count())
}

type loginReplayFixture struct {
	p                *Passkey
	users            *MockUserStore
	user             *MockUser
	userID           []byte
	token            string
	assertion        []byte
	invalidAssertion []byte
	authSessions     *loginReplayStore[UserSessionData]
}

// Only user persistence is mocked: challenge consumption and signature verification are real.
func newLoginReplayFixture(t *testing.T) *loginReplayFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := cbor.Marshal(map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(pub)})
	require.NoError(t, err)
	uid, cid := []byte("replay-user"), []byte("replay-credential")
	user := NewMockUser(t)
	user.On("WebAuthnID").Return(uid)
	user.On("WebAuthnName").Return("replay-user").Maybe()
	user.On("WebAuthnCredentials").Return([]webauthn.Credential{{ID: cid, PublicKey: key}})
	user.On("PutCredential", mock.Anything).Return().Maybe()
	users := NewMockUserStore(t)
	loginSessions := &loginReplayStore[webauthn.SessionData]{data: make(map[string]webauthn.SessionData)}
	authSessions := &loginReplayStore[UserSessionData]{data: make(map[string]UserSessionData)}
	p, err := New(Config{
		WebauthnConfig: &webauthn.Config{RPID: "example.com", RPDisplayName: "test", RPOrigins: []string{"https://example.com"}},
		UserStore:      users, LoginSessionStore: loginSessions, UserSessionStore: authSessions,
		RegistrationSessionStore: NewMockSessionStore[RegistrationSessionData](t),
	})
	require.NoError(t, err)
	users.On("GetByName", "replay-user").Return(user, nil).Once()
	begin := httptest.NewRecorder()
	p.mux.ServeHTTP(begin, httptest.NewRequest(http.MethodPost, pathLoginBegin, body("username", "replay-user")))
	require.Equal(t, http.StatusOK, begin.Code)
	cookies := begin.Result().Cookies()
	require.Len(t, cookies, 1)
	token := cookies[0].Value
	session, ok := loginSessions.Get(token)
	require.True(t, ok)
	require.NotNil(t, session)
	client, err := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": session.Challenge, "origin": "https://example.com"})
	require.NoError(t, err)
	rpHash := sha256.Sum256([]byte("example.com"))
	// User presence and verification, with a supported zero signature counter.
	auth := append(append([]byte{}, rpHash[:]...), 5, 0, 0, 0, 0)
	clientHash := sha256.Sum256(client)
	signature := ed25519.Sign(priv, append(append([]byte{}, auth...), clientHash[:]...))
	b64 := base64.RawURLEncoding.EncodeToString
	payload := map[string]any{
		"id": b64(cid), "rawId": b64(cid), "type": "public-key",
		"response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(signature), "userHandle": b64(uid)},
	}
	assertion, err := json.Marshal(payload)
	require.NoError(t, err)
	signature[0] ^= 1
	payload["response"].(map[string]string)["signature"] = b64(signature)
	invalid, err := json.Marshal(payload)
	require.NoError(t, err)
	return &loginReplayFixture{p: p, users: users, user: user, userID: uid, token: token, assertion: assertion, invalidAssertion: invalid, authSessions: authSessions}
}

func (f *loginReplayFixture) finish(payload []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, pathLoginFinish, bytes.NewReader(payload))
	req.AddCookie(&http.Cookie{Name: f.p.cookieSettings.loginSessionName, Value: f.token})
	rec := httptest.NewRecorder()
	f.p.mux.ServeHTTP(rec, req)
	return rec
}

func assertLoginCookieCleared(t *testing.T, p *Passkey, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name != p.cookieSettings.loginSessionName {
			continue
		}
		assert.Equal(t, -1, cookie.MaxAge)
		assert.Empty(t, cookie.Value)
		assert.Equal(t, "/", cookie.Path)
		assert.True(t, cookie.Secure)
		assert.True(t, cookie.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
		return
	}
	t.Error("response did not clear the login cookie")
}

type loginReplayStore[T any] struct {
	mu        sync.Mutex
	data      map[string]T
	nextID    int
	createErr error
}

func (s *loginReplayStore[T]) Create(data T) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		return "", s.createErr
	}
	s.nextID++
	token := fmt.Sprintf("test-session-%d", s.nextID)
	s.data[token] = data
	return token, nil
}

func (s *loginReplayStore[T]) Get(token string) (*T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	val, ok := s.data[token]
	if !ok {
		return nil, false
	}
	return &val, true
}

func (s *loginReplayStore[T]) Consume(token string) (*T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	val, ok := s.data[token]
	delete(s.data, token)
	if !ok {
		return nil, false
	}
	return &val, true
}

func (s *loginReplayStore[T]) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
}

func (s *loginReplayStore[T]) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data)
}

package passkey

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthRejectsInvalidSessionRecords(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for _, tt := range []struct {
		name string
		data *UserSessionData
	}{
		{"nil record", nil},
		{"legacy record", &UserSessionData{UserID: []byte("user"), Expires: future}},
		{"wrong purpose", &UserSessionData{Purpose: "passkey:login:v1", UserID: []byte("user"), Expires: future}},
		{"unknown version", &UserSessionData{Purpose: "passkey:user-session:v2", UserID: []byte("user"), Expires: future}},
		{"empty identity", &UserSessionData{Purpose: userSessionPurpose, Expires: future}},
		{"zero expiration", &UserSessionData{Purpose: userSessionPurpose, UserID: []byte("user")}},
		{"expired", &UserSessionData{Purpose: userSessionPurpose, UserID: []byte("user"), Expires: time.Now().Add(-time.Minute)}},
		{"deadline reached", &UserSessionData{Purpose: userSessionPurpose, UserID: []byte("user"), Expires: time.Now()}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMockSessionStore[UserSessionData](t)
			store.On("Get", "token").Return(tt.data, true).Once()
			p := &Passkey{userSessionStore: store}
			p.setupCookieSettings()
			succeeded, reached := false, false
			handler := p.Auth("user", func(http.ResponseWriter, *http.Request) {
				succeeded = true
			}, Unauthorized)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				reached = true
			}))
			req := httptest.NewRequest(http.MethodGet, "/private", http.NoBody)
			req.AddCookie(&http.Cookie{Name: p.cookieSettings.userSessionName, Value: "token"})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.False(t, succeeded)
			assert.False(t, reached)
		})
	}
}

func TestSessionPurposeWithSharedBackend(t *testing.T) {
	for _, codec := range []sessionTestCodec{
		{name: "JSON", encode: json.Marshal, decode: json.Unmarshal},
		{name: "gob", encode: func(v any) ([]byte, error) {
			var buf bytes.Buffer
			err := gob.NewEncoder(&buf).Encode(v)
			return buf.Bytes(), err
		}, decode: func(data []byte, v any) error {
			return gob.NewDecoder(bytes.NewReader(data)).Decode(v)
		}},
	} {
		t.Run(codec.name, func(t *testing.T) {
			f := newLoginReplayFixture(t)
			originalLoginStore := f.p.loginSessionStore
			records := &loginReplayStore[[]byte]{data: make(map[string][]byte)}
			loginStore := &encodedSessionStore[webauthn.SessionData]{records: records, codec: codec}
			userStore := &encodedSessionStore[UserSessionData]{records: records, codec: codec}
			f.p.loginSessionStore = loginStore
			f.p.userSessionStore = userStore
			f.users.On("GetByName", "replay-user").Return(f.user, nil).Once()
			begin := httptest.NewRecorder()
			f.p.mux.ServeHTTP(begin, httptest.NewRequest(http.MethodPost, pathLoginBegin, body("username", "replay-user")))
			require.Equal(t, http.StatusOK, begin.Code)
			cookies := begin.Result().Cookies()
			require.Len(t, cookies, 1)
			loginToken := cookies[0].Value
			decoded, ok := userStore.Get(loginToken)
			require.True(t, ok, "backend must permit cross-type decoding to exercise the attack")
			require.NotNil(t, decoded)
			assert.True(t, decoded.Expires.After(time.Now()))
			if codec.name == "gob" {
				assert.Equal(t, f.userID, decoded.UserID)
			}

			succeeded, reached := 0, 0
			key := AuthUserIDKey("user")
			protected := f.p.Auth(key, func(http.ResponseWriter, *http.Request) {
				succeeded++
			}, Unauthorized)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached++
				uid, valid := UserIDFromCtx(r.Context(), key)
				assert.True(t, valid)
				assert.Equal(t, f.userID, uid)
				w.WriteHeader(http.StatusNoContent)
			}))
			authorize := func(token string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodGet, "/private", http.NoBody)
				req.AddCookie(&http.Cookie{Name: f.p.cookieSettings.userSessionName, Value: token})
				rec := httptest.NewRecorder()
				protected.ServeHTTP(rec, req)
				return rec
			}
			assert.Equal(t, http.StatusUnauthorized, authorize(loginToken).Code)
			assert.Zero(t, succeeded)
			assert.Zero(t, reached)
			f.users.AssertNumberOfCalls(t, "Get", 0)

			// Move the fixture's signed ceremony into the same serialized backend.
			session, ok := originalLoginStore.Consume(f.token)
			require.True(t, ok)
			var err error
			f.token, err = loginStore.Create(*session)
			require.NoError(t, err)
			f.users.On("Get", f.userID).Return(f.user, nil).Once()
			f.users.On("Update", f.user).Return(nil).Once()
			finish := f.finish(f.assertion)
			require.Equal(t, http.StatusOK, finish.Code)
			var userToken string
			for _, cookie := range finish.Result().Cookies() {
				if cookie.Name == f.p.cookieSettings.userSessionName {
					userToken = cookie.Value
				}
			}
			require.NotEmpty(t, userToken)
			assert.Equal(t, http.StatusNoContent, authorize(userToken).Code)
			assert.Equal(t, 1, succeeded)
			assert.Equal(t, 1, reached)
		})
	}
}

type sessionTestCodec struct {
	name   string
	encode func(any) ([]byte, error)
	decode func([]byte, any) error
}

type encodedSessionStore[T any] struct {
	records *loginReplayStore[[]byte]
	codec   sessionTestCodec
}

func (s *encodedSessionStore[T]) Create(value T) (string, error) {
	data, err := s.codec.encode(value)
	if err != nil {
		return "", err
	}
	return s.records.Create(data)
}

func (s *encodedSessionStore[T]) Get(token string) (*T, bool) {
	data, ok := s.records.Get(token)
	return s.decode(data, ok)
}

func (s *encodedSessionStore[T]) Consume(token string) (*T, bool) {
	data, ok := s.records.Consume(token)
	return s.decode(data, ok)
}

func (s *encodedSessionStore[T]) decode(data *[]byte, ok bool) (*T, bool) {
	if !ok || data == nil {
		return nil, false
	}
	var value T
	if err := s.codec.decode(*data, &value); err != nil {
		return nil, false
	}
	return &value, true
}

func (s *encodedSessionStore[T]) Delete(token string) {
	s.records.Delete(token)
}

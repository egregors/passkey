package passkey

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/egregors/passkey/deps"
)

func TestMountedRoutesRejectOversizedBodies(t *testing.T) {
	for _, path := range []string{pathRegisterBegin, pathRegisterFinish, pathLoginBegin, pathLoginFinish} {
		for _, length := range []int64{maxRequestBodyBytes + 1, -1, 1} {
			for _, input := range []struct {
				name, prefix, suffix string
			}{
				{"large JSON string", `{"username":"`, `"}`},
				{"trailing whitespace", `{"username":"alice"}`, ""},
			} {
				t.Run(fmt.Sprintf("%s/length=%d/%s", path, length, input.name), func(t *testing.T) {
					// No dependencies may be called, including logging inside the handlers.
					p := &Passkey{
						cfg:                      Config{WebauthnConfig: &webauthn.Config{RPOrigins: []string{"https://example.com"}}},
						mux:                      http.NewServeMux(),
						log:                      NewMockLogger(t),
						webAuthn:                 deps.NewMockWebAuthnInterface(t),
						userStore:                NewMockUserStore(t),
						loginSessionStore:        NewMockSessionStore[webauthn.SessionData](t),
						registrationSessionStore: NewMockSessionStore[RegistrationSessionData](t),
						userSessionStore:         NewMockSessionStore[UserSessionData](t),
					}
					p.setupRoutes()
					mux := http.NewServeMux()
					p.MountRoutes(mux, "/api/")
					padding := strings.Repeat(" ", maxRequestBodyBytes+1-len(input.prefix)-len(input.suffix))
					payload := input.prefix + padding + input.suffix
					req := httptest.NewRequest(http.MethodPost, "/api"+path, strings.NewReader(payload))
					req.Header.Set("Origin", "https://example.com")
					req.ContentLength = length
					if length == -1 {
						req.TransferEncoding = []string{"chunked"}
					}
					rec := httptest.NewRecorder()
					mux.ServeHTTP(rec, req)
					assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
					assert.JSONEq(t, `"request body exceeds 1 MiB"`, rec.Body.String())
					assert.Empty(t, rec.Result().Cookies())
				})
			}
		}
	}
}

func TestLimitRequestBodyBoundaries(t *testing.T) {
	for _, size := range []int{0, maxRequestBodyBytes - 1, maxRequestBodyBytes, maxRequestBodyBytes + 1, 2 * maxRequestBodyBytes} {
		t.Run(fmt.Sprintf("bytes=%d", size), func(t *testing.T) {
			payload := bytes.Repeat([]byte("x"), size)
			body := &trackedRequestBody{Reader: bytes.NewReader(payload)}
			req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
			req.Body = body
			rec := httptest.NewRecorder()
			called := false
			limitRequestBody(func(w http.ResponseWriter, r *http.Request) {
				called = true
				got, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.Equal(t, payload, got)
				w.WriteHeader(http.StatusNoContent)
			})(rec, req)
			assert.True(t, body.closed)
			assert.LessOrEqual(t, body.bytesRead, maxRequestBodyBytes+1)
			if size > maxRequestBodyBytes {
				assert.False(t, called)
				assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
			} else {
				assert.True(t, called)
				assert.Equal(t, http.StatusNoContent, rec.Code)
			}
		})
	}
}

func TestLimitRequestBodyReadError(t *testing.T) {
	body := &trackedRequestBody{Reader: iotest.ErrReader(errors.New("private read error"))}
	req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
	req.Body = body
	rec := httptest.NewRecorder()
	limitRequestBody(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run after a body read error")
	})(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.JSONEq(t, `"can't read request body"`, rec.Body.String())
	assert.True(t, body.closed)
}

func TestBeginRoutesRejectLongUsernames(t *testing.T) {
	for _, path := range []string{pathRegisterBegin, pathLoginBegin} {
		for _, name := range []string{strings.Repeat("a", 257), strings.Repeat("я", 129), strings.Repeat(`\u0061`, 257)} {
			t.Run(fmt.Sprintf("%s/bytes=%d", path, len(name)), func(t *testing.T) {
				logger := NewMockLogger(t)
				logger.On("Infof", mock.Anything).Return()
				logger.On("Debugf", mock.Anything).Return()
				logger.On("Errorf", "%s", mock.Anything).Return()
				p := &Passkey{
					cfg:       Config{WebauthnConfig: &webauthn.Config{RPOrigins: []string{"https://example.com"}}},
					mux:       http.NewServeMux(),
					log:       logger,
					userStore: NewMockUserStore(t),
					webAuthn:  deps.NewMockWebAuthnInterface(t),
				}
				p.setupRoutes()
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"username":"`+name+`"}`))
				req.Header.Set("Origin", "https://example.com")
				rec := httptest.NewRecorder()
				p.mux.ServeHTTP(rec, req)
				assert.Equal(t, http.StatusBadRequest, rec.Code)
				assert.Contains(t, rec.Body.String(), ErrUsernameTooLong.Error())
			})
		}
	}
}

func TestUsernameByteLimit(t *testing.T) {
	for _, name := range []string{strings.Repeat("a", 256), strings.Repeat("я", 128)} {
		req := httptest.NewRequest(http.MethodPost, "/", body("username", name))
		got, err := getUsername(req)
		require.NoError(t, err)
		assert.Equal(t, name, got)
	}
}

type trackedRequestBody struct {
	io.Reader
	bytesRead int
	closed    bool
}

func (b *trackedRequestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytesRead += n
	return n, err
}

func (b *trackedRequestBody) Close() error {
	b.closed = true
	return nil
}

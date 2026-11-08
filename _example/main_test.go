package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/egregors/passkey"
)

func TestPrivateHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		user   passkey.User
		err    error
		withID bool
		status int
		body   string
	}{
		{name: "no identity", status: http.StatusUnauthorized, body: "No user found"},
		{name: "deleted user", withID: true, err: fmt.Errorf("lookup: %w", passkey.ErrUserNotFound), status: http.StatusUnauthorized, body: "No user found"},
		{name: "storage failure", withID: true, err: errors.New("private backend diagnostic"), status: http.StatusInternalServerError, body: "Internal server error"},
		{name: "nil user", withID: true, status: http.StatusInternalServerError, body: "Internal server error"},
		{name: "escaped name", withID: true, user: &User{Name: "<alice>"}, status: http.StatusOK, body: "Hi, &lt;alice&gt;!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := passkey.NewMockUserStore(t)
			r := httptest.NewRequest(http.MethodGet, "/private", http.NoBody)
			if tc.withID {
				users.EXPECT().Get([]byte("user")).Return(tc.user, tc.err)
				r = r.WithContext(context.WithValue(r.Context(), userKey, []byte("user")))
			}
			w := httptest.NewRecorder()
			privateHandler(users).ServeHTTP(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.body) {
				t.Fatalf("got %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private backend diagnostic") {
				t.Fatal("leaked storage diagnostic")
			}
		})
	}
}

func TestExampleRegistrationLoginPrivateLogout(t *testing.T) {
	const origin = "https://example.com"
	users := NewUserStore()
	pkey, err := passkey.New(passkey.Config{
		WebauthnConfig:           &webauthn.Config{RPDisplayName: "Example", RPID: "example.com", RPOrigins: []string{origin}},
		UserStore:                users,
		LoginSessionStore:        NewSessionStore[webauthn.SessionData](),
		RegistrationSessionStore: NewSessionStore[passkey.RegistrationSessionData](),
		UserSessionStore:         NewSessionStore[passkey.UserSessionData](),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := exampleMux(pkey, users)
	cookies := map[string]*http.Cookie{}
	request := func(method, path string, body any, status int) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, origin+path, bytes.NewReader(data))
		if method == http.MethodPost {
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: got %d: %s", method, path, w.Code, w.Body.String())
		}
		for _, cookie := range w.Result().Cookies() {
			if cookie.MaxAge < 0 {
				delete(cookies, cookie.Name)
			} else {
				cookies[cookie.Name] = cookie
			}
		}
		return w
	}
	options := func(w *httptest.ResponseRecorder) (challenge, userID string) {
		t.Helper()
		var result struct {
			PublicKey struct {
				Challenge string
				User      struct{ ID string }
			}
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.PublicKey.Challenge == "" {
			t.Fatal("missing challenge")
		}
		return result.PublicKey.Challenge, result.PublicKey.User.ID
	}
	encode := base64.RawURLEncoding.EncodeToString
	marshal := func(v any) []byte {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	marshalCBOR := func(v any) []byte {
		t.Helper()
		data, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := []byte("smoke-credential")
	rpHash := sha256.Sum256([]byte("example.com"))
	challenge, userID := options(request(http.MethodPost, "/api/passkey/registerBegin", map[string]string{"username": "alice"}, http.StatusOK))
	clientData := marshal(map[string]string{"type": "webauthn.create", "challenge": challenge, "origin": origin})
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x45, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, marshalCBOR(map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(pub)})...)
	attestation := marshalCBOR(map[string]any{"fmt": "none", "authData": authData, "attStmt": map[string]any{}})
	request(http.MethodPost, "/api/passkey/registerFinish", map[string]any{
		"id": encode(credentialID), "rawId": encode(credentialID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": encode(clientData), "attestationObject": encode(attestation), "transports": []string{"internal"}},
	}, http.StatusOK)
	request(http.MethodGet, "/private", nil, http.StatusSeeOther)
	challenge, _ = options(request(http.MethodPost, "/api/passkey/loginBegin", map[string]string{"username": "alice"}, http.StatusOK))
	clientData = marshal(map[string]string{"type": "webauthn.get", "challenge": challenge, "origin": origin})
	authData = append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x05, 0, 0, 0, 1)
	clientHash := sha256.Sum256(clientData)
	signature := ed25519.Sign(priv, append(append([]byte{}, authData...), clientHash[:]...))
	request(http.MethodPost, "/api/passkey/loginFinish", map[string]any{
		"id": encode(credentialID), "rawId": encode(credentialID), "type": "public-key",
		"response": map[string]string{"clientDataJSON": encode(clientData), "authenticatorData": encode(authData), "signature": encode(signature), "userHandle": userID},
	}, http.StatusOK)
	w := request(http.MethodGet, "/private", nil, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Hi, alice!") {
		t.Fatal("private page did not resolve the registered user")
	}
	user, err := users.GetByName("alice")
	if err != nil {
		t.Fatal(err)
	}
	credentials := user.WebAuthnCredentials()
	if len(credentials) != 1 || credentials[0].Authenticator.SignCount != 1 {
		t.Fatalf("credential state: %+v", credentials)
	}
	users.mu.Lock()
	delete(users.users, "alice")
	users.mu.Unlock()
	request(http.MethodGet, "/private", nil, http.StatusUnauthorized)
	request(http.MethodPost, "/logout", nil, http.StatusNoContent)
	request(http.MethodGet, "/private", nil, http.StatusSeeOther)
}

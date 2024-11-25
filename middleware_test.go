package passkey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

func TestAuth(t *testing.T) {
	type args struct {
		userSessionStore func() SessionStore[UserSessionData]
		onSuccess        http.HandlerFunc
		onFail           http.HandlerFunc
		req              func() *http.Request
	}
	tests := []struct {
		name            string
		args            args
		wantStatus      int
		wantExtraHeader func(wH, rH http.Header) bool
	}{
		{
			name: "200: session is valid",
			args: args{
				userSessionStore: func() SessionStore[UserSessionData] {
					store := NewMockSessionStore[UserSessionData](t)
					store.EXPECT().
						Get("valid").
						Return(&UserSessionData{
							UserID:  []byte("42"),
							Expires: time.Now().Add(time.Hour),
						}, true).
						Times(1)

					return store
				},
				onSuccess: nil,
				onFail:    Unauthorized,
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
					req.AddCookie(&http.Cookie{
						Name:  camelCaseConcat(defaultSessionNamePrefix, defaultUserSessionName),
						Value: "valid",
					})

					return req
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "200: session is valid and onSuccess handler is called",
			args: args{
				userSessionStore: func() SessionStore[UserSessionData] {
					store := NewMockSessionStore[UserSessionData](t)
					store.EXPECT().
						Get("valid").
						Return(&UserSessionData{
							UserID:  []byte("42"),
							Expires: time.Now().Add(time.Hour),
						}, true).
						Times(1)

					return store
				},
				onSuccess: func(w http.ResponseWriter, r *http.Request) {
					// add extra header to request
					r.Header.Add("Cat", "Berik")
				},
				onFail: nil,
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
					req.AddCookie(&http.Cookie{
						Name:  camelCaseConcat(defaultSessionNamePrefix, defaultUserSessionName),
						Value: "valid",
					})

					return req
				},
			},
			wantStatus: http.StatusOK,
			wantExtraHeader: func(wH, rH http.Header) bool {
				return rH.Get("Cat") == "Berik"
			},
		},
		{
			name: "401: missing session + redirect to target URL",
			args: args{
				userSessionStore: func() SessionStore[UserSessionData] {
					store := NewMockSessionStore[UserSessionData](t)
					store.EXPECT().
						Get("missing").
						Return(nil, false).
						Times(1)

					return store
				},
				onSuccess: nil,
				onFail: RedirectUnauthorized(url.URL{
					Path: "/login",
				}),
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
					req.AddCookie(&http.Cookie{
						Name:  camelCaseConcat(defaultSessionNamePrefix, defaultUserSessionName),
						Value: "missing",
					})

					return req
				},
			},
			wantStatus: http.StatusSeeOther,
			wantExtraHeader: func(wH, rH http.Header) bool {
				return wH.Get("Location") == "/login"
			},
		},
		{
			name: "401: missing session cookie",
			args: args{
				userSessionStore: func() SessionStore[UserSessionData] {
					return NewMockSessionStore[UserSessionData](t)
				},
				onSuccess: nil,
				onFail:    Unauthorized,
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)

					return req
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "401: missing session",
			args: args{
				userSessionStore: func() SessionStore[UserSessionData] {
					store := NewMockSessionStore[UserSessionData](t)
					store.EXPECT().
						Get("missing").
						Return(nil, false).
						Times(1)

					return store
				},
				onSuccess: nil,
				onFail:    Unauthorized,
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
					req.AddCookie(&http.Cookie{
						Name:  camelCaseConcat(defaultSessionNamePrefix, defaultUserSessionName),
						Value: "missing",
					})

					return req
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "401: session expired",
			args: args{
				userSessionStore: func() SessionStore[UserSessionData] {
					store := NewMockSessionStore[UserSessionData](t)
					store.EXPECT().
						Get("expired").
						Return(&UserSessionData{
							UserID:  []byte("42"),
							Expires: time.Now().Add(-time.Hour),
						}, true).
						Times(1)

					return store
				},
				onSuccess: nil,
				onFail:    Unauthorized,
				req: func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
					req.AddCookie(&http.Cookie{
						Name:  camelCaseConcat(defaultSessionNamePrefix, defaultUserSessionName),
						Value: "expired",
					})

					return req
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		p, err := New(
			Config{
				WebauthnConfig: &webauthn.Config{
					RPDisplayName: "Passkey Test",
					RPID:          "localhost",
					RPOrigins:     []string{"localhost"},
				},
				UserStore:        NewMockUserStore(t),
				AuthSessionStore: NewMockSessionStore[webauthn.SessionData](t),
				UserSessionStore: tt.args.userSessionStore(),
			},
		)
		assert.NoError(t, err)
		t.Run(tt.name, func(t *testing.T) {
			handler := p.Auth(
				"pkUserKey",
				tt.args.onSuccess,
				tt.args.onFail,
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := tt.args.req()
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)

			if resp.Code != tt.wantStatus {
				t.Errorf("Auth() = %v, want %v", resp.Code, tt.wantStatus)
			}

			if tt.wantExtraHeader != nil && !tt.wantExtraHeader(resp.Header(), req.Header) {
				t.Errorf("Wrong Header: %v", req.Header)
			}
		})
	}
}

func TestUserFromContext(t *testing.T) {
	tests := []struct {
		name      string
		ctx       context.Context
		pkUserKey string
		wantVal   []byte
		wantOk    bool
	}{
		{
			name:      "empty context",
			ctx:       context.Background(),
			pkUserKey: "pkUserKey",
			wantVal:   nil,
			wantOk:    false,
		},
		{
			name:      "missing key",
			ctx:       context.WithValue(context.Background(), "otherKey", "value"),
			pkUserKey: "pkUserKey",
			wantVal:   nil,
			wantOk:    false,
		},
		{
			name:      "empty value",
			ctx:       context.WithValue(context.Background(), "pkUserKey", ""),
			pkUserKey: "pkUserKey",
			wantVal:   nil,
			wantOk:    false,
		},
		{
			name:      "valid value",
			ctx:       context.WithValue(context.Background(), "pkUserKey", []byte("value")),
			pkUserKey: "pkUserKey",
			wantVal:   []byte("value"),
			wantOk:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotOk := UserIDFromCtx(tt.ctx, tt.pkUserKey)
			assert.Equalf(t, tt.wantVal, gotVal, "UserIDFromCtx(%v, %v)", tt.ctx, tt.pkUserKey)
			assert.Equalf(t, tt.wantOk, gotOk, "UserIDFromCtx(%v, %v)", tt.ctx, tt.pkUserKey)
		})
	}
}

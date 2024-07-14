package passkey

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestAuth(t *testing.T) {
	type args struct {
		sessionStore func() SessionStore
		onSuccess    http.HandlerFunc
		onFail       http.HandlerFunc
		req          http.Request
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
				sessionStore: func() SessionStore {
					store := NewMockSessionStore(t)
					store.EXPECT().
						GetSession("valid").
						Return(&webauthn.SessionData{
							Expires: time.Now().Add(time.Hour),
						}, true).
						Times(1)

					return store
				},
				onSuccess: nil,
				onFail:    Unauthorized,
				req: http.Request{
					Header: http.Header{
						"Cookie": []string{"sid=valid"},
					},
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "200: session is valid and onSuccess handler is called",
			args: args{
				sessionStore: func() SessionStore {
					store := NewMockSessionStore(t)
					store.EXPECT().
						GetSession("valid").
						Return(&webauthn.SessionData{
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
				req: http.Request{
					Header: http.Header{
						"Cookie": []string{"sid=valid"},
					},
				},
			},
			wantStatus: http.StatusOK,
			wantExtraHeader: func(wH, rH http.Header) bool {
				return rH.Get("Cat") == "Berik"
			},
		},
		{
			name: "401: redirect to target URL",
			args: args{
				sessionStore: func() SessionStore {
					store := NewMockSessionStore(t)
					store.EXPECT().
						GetSession("missing").
						Return(nil, false).
						Times(1)

					return store
				},
				onSuccess: nil,
				onFail: RedirectUnauthorized(url.URL{
					Path: "/login",
				}),
				req: http.Request{
					Header: http.Header{
						"Cookie": []string{"sid=missing"},
					},
					URL: &url.URL{Path: "/"},
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
				sessionStore: func() SessionStore {
					return NewMockSessionStore(t)
				},
				onSuccess: nil,
				onFail:    Unauthorized,
				req: http.Request{
					Header: http.Header{},
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "401: missing session",
			args: args{
				sessionStore: func() SessionStore {
					store := NewMockSessionStore(t)
					store.EXPECT().
						GetSession("missing").
						Return(nil, false).
						Times(1)

					return store
				},
				onSuccess: nil,
				onFail:    Unauthorized,
				req: http.Request{
					Header: http.Header{
						"Cookie": []string{"sid=missing"},
					},
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "401: session expired",
			args: args{
				sessionStore: func() SessionStore {
					store := NewMockSessionStore(t)
					store.EXPECT().
						GetSession("expired").
						Return(&webauthn.SessionData{
							Expires: time.Now().Add(-time.Hour),
						}, true).
						Times(1)

					return store
				},
				onSuccess: nil,
				onFail:    Unauthorized,
				req: http.Request{
					Header: http.Header{
						"Cookie": []string{"sid=expired"},
					},
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStore := tt.args.sessionStore()
			handler := Auth(sessionStore, tt.args.onSuccess, tt.args.onFail)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, &tt.args.req)

			if resp.Code != tt.wantStatus {
				t.Errorf("Auth() = %v, want %v", resp.Code, tt.wantStatus)
			}

			if tt.wantExtraHeader != nil && !tt.wantExtraHeader(resp.Header(), tt.args.req.Header) {
				t.Errorf("Wrong Header: %v", tt.args.req.Header)
			}
		})
	}
}

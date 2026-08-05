package passkey

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AuthUserIDKey string

// Auth implements a middleware handler for adding passkey http auth to a route.
// It checks if the request has a valid session cookie and if the session is still valid.
// If the session is valid:
//   - `UserID` will be added to the request context;
//   - `onSuccess` handler is called and the next handler is executed.
//
// Otherwise:
//   - `onFail` handler is called and the next handler is not executed.
func (p *Passkey) Auth(userIDKey AuthUserIDKey, onSuccess, onFail http.HandlerFunc) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sid, err := r.Cookie(p.cookieSettings.userSessionName)
			if err != nil {
				exec(onFail, w, r)

				return
			}

			session, ok := p.userSessionStore.Get(sid.Value)
			if !ok {
				exec(onFail, w, r)

				return
			}

			if session.Expires.Before(time.Now()) {
				exec(onFail, w, r)

				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, session.UserID)
			r = r.WithContext(ctx)

			exec(onSuccess, w, r)
			next.ServeHTTP(w, r)
		})
	}
}

func exec(handlerFunc http.HandlerFunc, w http.ResponseWriter, r *http.Request) {
	if handlerFunc != nil {
		handlerFunc(w, r)
	}
}

// Unauthorized writes a 401 Unauthorized status code to the response.
func Unauthorized(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
}

// RedirectUnauthorized redirects the user to the target URL with a 401 Unauthorized status code.
func RedirectUnauthorized(target url.URL) http.HandlerFunc {
	if !isLocalRedirectTarget(target) {
		return Unauthorized
	}

	targetURL := target.String()

	return func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // G710: target is validated as a local URL before the closure is created.
		http.Redirect(w, r, targetURL, http.StatusSeeOther)
	}
}

func isLocalRedirectTarget(target url.URL) bool {
	if target.IsAbs() || target.Host != "" || target.User != nil || target.Opaque != "" {
		return false
	}

	// Network-path references (//host/path) and backslashes can be interpreted
	// as cross-origin URLs by user agents even when URL.Scheme is empty.
	return !strings.HasPrefix(target.Path, "//") && !strings.Contains(target.Path, `\`)
}

// UserIDFromCtx returns the user ID from the request context. If the userID is not found, it returns nil and false.
func UserIDFromCtx(ctx context.Context, pkUserKey AuthUserIDKey) ([]byte, bool) {
	if ctx.Value(pkUserKey) == nil {
		return nil, false
	}

	if id, ok := ctx.Value(pkUserKey).([]byte); ok && len(id) > 0 {
		return id, true
	}

	return nil, false
}

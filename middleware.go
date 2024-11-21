package passkey

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Auth implements a middleware handler for adding passkey http auth to a route.
// It checks if the request has a valid session cookie and if the session is still valid.
// If the session is valid:
//   - `UserID` will be added to the request context;
//   - `onSuccess` handler is called and the next handler is executed.
//
// Otherwise:
//   - `onFail` handler is called and the next handler is not executed.
func (p *Passkey) Auth(userIDKey string, onSuccess, onFail http.HandlerFunc) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sid, err := r.Cookie(p.cookieSettings.Name)
			if err != nil {
				exec(onFail, w, r)

				return
			}

			// FIXME: i shouldn't use registration \ authorization session store here
			//   it should be a separate store with a mach lighter session object
			session, ok := p.userSessionStore.Get(sid.Value)
			if !ok {
				exec(onFail, w, r)

				return
			}

			if session.Expires.Before(time.Now()) {
				exec(onFail, w, r)

				return
			}

			ctx := r.Context()
			// TODO: add username as well?
			ctx = context.WithValue(ctx, userIDKey, string(session.UserID))
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
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.String(), http.StatusSeeOther)
	}
}

// UserFromContext returns the user ID from the request context. If the userID is not found, it returns an empty string.
func UserFromContext(ctx context.Context, pkUserKey string) (string, bool) {
	if ctx.Value(pkUserKey) == nil {
		return "", false
	}

	if id, ok := ctx.Value(pkUserKey).(string); ok && id != "" {
		return id, true
	}

	return "", false
}

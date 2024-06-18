package passkey

import (
	"net/http"
	"time"
)

// Auth implements a middleware handler for adding passkey http auth to a route.
//
// TODO:
//   - cookie name should be configurable
//   - fallback to a login page if not authenticated
//   - fallback must be configurable as well
func Auth(sessionStore SessionStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: cookie name should be configurable
			sid, err := r.Cookie("sid")
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			session, ok := sessionStore.GetSession(sid.Value)
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if session.Expires.Before(time.Now()) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

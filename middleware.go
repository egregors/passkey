package passkey

import (
	"net/http"
	"net/url"
	"time"
)

// Auth implements a middleware handler for adding passkey http auth to a route.
// It checks if the request has a valid session cookie and if the session is still valid.
// If the session is valid, the onSuccess handler is called and the next handler is executed.
// If the session is invalid, the onFail handler is called and the next handler is not executed.
func Auth(sessionStore SessionStore, onSuccess, onFail http.HandlerFunc) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sid, err := r.Cookie(sessionCookieName)
			if err != nil {
				exec(onFail, w, r)

				return
			}

			session, ok := sessionStore.GetSession(sid.Value)
			if !ok {
				exec(onFail, w, r)

				return
			}

			if session.Expires.Before(time.Now()) {
				exec(onFail, w, r)

				return
			}

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
		http.Redirect(w, r, target.String(), http.StatusUnauthorized)
	}
}

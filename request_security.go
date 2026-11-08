package passkey

import (
	"fmt"
	"net/http"
	"slices"
)

func (p *Passkey) mutationHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.allowMutation(w, r) {
			next(w, r)
		}
	}
}

func (p *Passkey) allowMutation(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		JSONResponse(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] == "" || origins[0] == "null" || !slices.Contains(p.cfg.WebauthnConfig.RPOrigins, origins[0]) {
		JSONResponse(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	return true
}

func sessionCookie(r *http.Request, name string) (*http.Cookie, error) {
	cookies := r.CookiesNamed(name)
	if len(cookies) == 0 {
		return nil, http.ErrNoCookie
	}
	if len(cookies) != 1 {
		return nil, fmt.Errorf("duplicate session cookie")
	}
	return cookies[0], nil
}

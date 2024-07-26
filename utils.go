package passkey

import "net/http"

// Logout deletes session from session store and deletes session cookie
func (p *Passkey) Logout(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie(sessionCookieName)
	if err != nil {
		p.l.Errorf("can't get session cookie: %s", err.Error())

		return
	}

	p.sessionStore.DeleteSession(sid.Value)
	deleteCookie(w, sessionCookieName)
}

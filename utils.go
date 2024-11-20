package passkey

import "net/http"

// Logout deletes session from session store and deletes session cookie
func (p *Passkey) Logout(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie(p.cookieSettings.Name)
	if err != nil {
		p.log.Errorf("can't get session cookie: %s", err.Error())

		return
	}

	p.sessionStore.Delete(sid.Value)
	p.deleteSessionCookie(w)
}

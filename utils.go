package passkey

import (
	"net/http"
	"time"
)

// Logout deletes session from session store and deletes session cookie
// TODO: put it somewhere else
func (p *Passkey) Logout(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie(p.cookieSettings.userSessionName)
	if err != nil {
		p.log.Errorf("can't get session cookie: %s", err.Error())

		return
	}

	p.authSessionStore.Delete(sid.Value)
	http.SetCookie(w, &http.Cookie{
		Name:    p.cookieSettings.userSessionName,
		Value:   "",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
}

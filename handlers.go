package passkey

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (p *Passkey) beginRegistration(w http.ResponseWriter, r *http.Request) {
	p.log.Infof(">>> begin registration")

	var err error
	defer func() {
		if err != nil {
			p.log.Errorf("%s", err.Error())
			JSONResponse(w, err.Error(), http.StatusBadRequest)
			p.log.Debugf("begin registration: done with error")
		}
	}()

	p.log.Debugf("got request: %v", r)
	username, err := getUsername(r)
	if err != nil {
		err = fmt.Errorf("can't get username: %w", err)

		return
	}
	p.log.Debugf("got username: %s", username)

	p.log.Debugf("try to create user")
	user, err := p.userStore.Create(username)
	if err != nil {
		err = fmt.Errorf("can't create user: %w", err)

		return
	}
	p.log.Debugf("user created: %s", user.WebAuthnName())

	p.log.Debugf("try to get options from webauthn")
	options, session, err := p.webAuthn.BeginRegistration(user)
	if err != nil {
		err = fmt.Errorf("can't begin registration: %w", err)

		return
	}
	p.log.Debugf("got options")

	p.log.Debugf("try to save session")
	t, err := p.authSessionStore.Create(*session)
	if err != nil {
		err = fmt.Errorf("can't save session: %w", err)

		return
	}
	p.log.Debugf("session saved: %s", t)

	p.log.Debugf("setting cookie")
	p.setSessionCookie(w, t)

	// return the options generated with the session key
	// options.publicKey contain our registration options
	JSONResponse(w, options, http.StatusOK)

	p.log.Infof("<<< begin registration: done")
}

func (p *Passkey) finishRegistration(w http.ResponseWriter, r *http.Request) {
	p.log.Infof(">>> finish registration")

	var err error
	defer func() {
		if err != nil {
			p.log.Errorf("%s", err.Error())
			JSONResponse(w, err.Error(), http.StatusBadRequest)
			p.log.Debugf("cleaned up session cookie")
			p.log.Debugf("<<< finish registration: done with error")
		}
		p.deleteSessionCookie(w)
	}()

	// Get the session key from cookie
	p.log.Debugf("getting session id from cookie")
	sid, err := r.Cookie(p.cookieSettings.Name)
	if err != nil {
		err = fmt.Errorf("can't get session id: %w", err)

		return
	}
	p.log.Debugf("got session id: %s", sid.Value)

	// Get the session data stored from the function above
	p.log.Debugf("try to get session data")
	session, ok := p.authSessionStore.Get(sid.Value)
	if !ok {
		err = fmt.Errorf("can't get session data")

		return
	}
	p.log.Debugf("got session data")

	p.log.Debugf("try to get user from repo")
	user, err := p.userStore.Get(session.UserID)
	if err != nil {
		err = fmt.Errorf("can't get user: %w", err)

		return
	}
	p.log.Debugf("got user: %s", user.WebAuthnName())

	p.log.Debugf("try to get credential from webauthn")
	credential, err := p.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		err = fmt.Errorf("can't finish registration: %w", err)

		return
	}
	p.log.Debugf("got credential")

	p.log.Debugf("putting credential to user")
	user.PutCredential(*credential)
	p.log.Debugf("try to save user")
	err = p.userStore.Update(user)
	if err != nil {
		err = fmt.Errorf("can't save user: %w", err)

		return
	}
	p.log.Debugf("user saved")

	p.log.Debugf("deleting session data")
	p.authSessionStore.Delete(sid.Value)

	JSONResponse(w, "Registration Success", http.StatusOK)

	p.log.Infof("<<< finish registration: done")
}

func (p *Passkey) beginLogin(w http.ResponseWriter, r *http.Request) {
	p.log.Infof(">>> begin login")

	var err error
	defer func() {
		if err != nil {
			p.log.Errorf("%s", err.Error())
			JSONResponse(w, err.Error(), http.StatusBadRequest)
			p.log.Debugf("<<< begin login: done with error")
		}
	}()

	p.log.Debugf("got request: %v", r)
	username, err := getUsername(r)
	if err != nil {
		err = fmt.Errorf("can't get username: %w", err)

		return
	}
	p.log.Debugf("got username: %s", username)

	p.log.Debugf("try to get user")
	user, err := p.userStore.GetByName(username)
	if err != nil {
		err = fmt.Errorf("can't get user: %w", err)

		return
	}
	p.log.Debugf("got user: %s", user.WebAuthnName())

	p.log.Debugf("try to get options from webauthn")
	options, session, err := p.webAuthn.BeginLogin(user)
	if err != nil {
		err = fmt.Errorf("can't begin login: %w", err)
		p.deleteSessionCookie(w)

		return
	}
	p.log.Debugf("got options")

	p.log.Debugf("try to save session")
	t, err := p.authSessionStore.Create(*session)
	if err != nil {
		err = fmt.Errorf("can't save session: %w", err)

		return
	}
	p.log.Debugf("session saved: %s", t)

	p.log.Debugf("setting cookie")
	p.setSessionCookie(w, t)

	// return the options generated with the session key
	// options.publicKey contain our registration options
	JSONResponse(w, options, http.StatusOK)

	p.log.Infof("<<< begin login: done")
}

func (p *Passkey) finishLogin(w http.ResponseWriter, r *http.Request) {
	p.log.Infof(">>> finish login")

	var err error
	defer func() {
		if err != nil {
			p.log.Errorf("%s", err.Error())
			JSONResponse(w, err.Error(), http.StatusBadRequest)
			p.log.Debugf("<<< finish login: done with error")
		}
	}()

	// Get the session key from cookie
	p.log.Debugf("getting session id from cookie")
	sid, err := r.Cookie(p.cookieSettings.Name)
	if err != nil {
		err = fmt.Errorf("can't get session id: %w", err)

		return
	}
	p.log.Debugf("got session id: %s", sid.Value)

	// Get the session data stored from the function above
	p.log.Debugf("try to get session data")
	session, ok := p.authSessionStore.Get(sid.Value)
	if !ok {
		err = fmt.Errorf("can't get session data")

		return
	}
	p.log.Debugf("got session data")

	p.log.Debugf("try to get user from repo")
	user, err := p.userStore.Get(session.UserID)
	if err != nil {
		err = fmt.Errorf("can't get user: %w", err)

		return
	}
	p.log.Debugf("got user: %s", user.WebAuthnName())

	p.log.Debugf("try to get credential from webauthn")
	credential, err := p.webAuthn.FinishLogin(user, *session, r)
	if err != nil {
		err = fmt.Errorf("can't finish login: %w", err)

		return
	}
	p.log.Debugf("got credential")

	// Handle credential.Authenticator.CloneWarning
	if credential.Authenticator.CloneWarning {
		p.log.Warnf("the authenticator may be cloned")
	}

	// If login was successful, update the credential object
	p.log.Debugf("putting credential to user")
	// TODO: put? save? update?
	p.log.Debugf("try to save user")
	user.PutCredential(*credential)
	err = p.userStore.Update(user)
	if err != nil {
		err = fmt.Errorf("can't save user: %w", err)

		return
	}
	p.log.Debugf("user saved")

	// Delete the login session data
	p.log.Debugf("deleting session data and cookie")
	p.authSessionStore.Delete(sid.Value)
	p.deleteSessionCookie(w)

	p.log.Debugf("try to save user session")
	t, err := p.userSessionStore.Create(UserSessionData{
		UserID:  session.UserID,
		Expires: time.Now().Add(p.cfg.UserSessionMaxAge),
	})
	if err != nil {
		err = fmt.Errorf("can't save user session: %w", err)

		return
	}
	p.log.Debugf("session saved: %s", t)

	p.log.Debugf("setting cookie")
	p.setSessionCookie(w, t)

	JSONResponse(w, "Login Success", http.StatusOK)

	p.log.Infof("<<< finish login")
}

// setSessionCookie sets a cookie
func (p *Passkey) setSessionCookie(w http.ResponseWriter, value string) {
	// FIXME: now we user maxAge setting from consumer. But we actually need to use it
	//  only for userSession. Looks like maxAge for authSession we must set strictly
	http.SetCookie(w, &http.Cookie{
		Name:     p.cookieSettings.Name,
		Value:    value,
		Path:     p.cookieSettings.Path,
		MaxAge:   int(p.cookieSettings.MaxAge.Seconds()),
		Secure:   p.cookieSettings.Secure,
		HttpOnly: p.cookieSettings.HttpOnly,
		SameSite: p.cookieSettings.SameSite,
	})
}

// deleteSessionCookie deletes a cookie
func (p *Passkey) deleteSessionCookie(w http.ResponseWriter) { //nolint:unparam // it's ok here
	http.SetCookie(w, &http.Cookie{
		Name:    p.cookieSettings.Name,
		Value:   "",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
}

// getUsername extracts an username from json request
func getUsername(r *http.Request) (string, error) {
	var u struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return "", err
	}

	if u.Username == "" {
		return "", ErrNoUsername
	}

	return u.Username, nil
}

// JSONResponse sends json response
func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

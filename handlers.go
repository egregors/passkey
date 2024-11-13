package passkey

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type payload struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
}

func (p *Passkey) beginRegistration(w http.ResponseWriter, r *http.Request) {
	p.l.Infof("begin registration")

	userData, err := p.parsePayload(r)
	if err != nil {
		msg := fmt.Sprintf("bad payload: %s", err.Error())
		p.l.Errorf(msg)
		JSONResponse(w, fmt.Sprintf("beginRegistration failed: %s", msg), http.StatusBadRequest)

		return
	}

	// get or create user
	user := cmp.Or(
		p.userStore.Get(userData.Name),
		p.userStore.New(
			p.genUserID(),
			userData.Name,
			userData.DisplayName,
		),
	)

	options, session, err := p.webAuthn.BeginRegistration(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin registration: %s", err.Error())
		p.l.Errorf(msg)
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	// Make a session key and store the sessionData values
	t, err := p.sessionStore.GenSessionID()
	if err != nil {
		p.l.Errorf("can't generate session id: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't generate session id: %s", err.Error()), http.StatusInternalServerError)

		return
	}

	p.sessionStore.SaveSession(t, session)
	p.setSessionCookie(w, t)

	// return the options generated with the session key
	// options.publicKey contain our registration options
	JSONResponse(w, options, http.StatusOK)
}

func (p *Passkey) finishRegistration(w http.ResponseWriter, r *http.Request) {
	// Get the session key from cookie
	sid, err := r.Cookie(p.cookieSettings.Name)
	if err != nil {
		p.l.Errorf("can't get session id: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't get session id: %s", err.Error()), http.StatusBadRequest)

		return
	}

	// Get the session data stored from the function above
	session, ok := p.sessionStore.GetSession(sid.Value)
	if !ok {
		p.l.Errorf("can't get session data")
		JSONResponse(w, "can't get session data", http.StatusBadRequest)

		return
	}

	// TODO: username != user id? need to check
	// user := p.userStore.GetOrCreateUser(string(session.UserID)) // Get the user
	user := p.userStore.Get(string(session.UserID))
	if user == nil {
		p.l.Errorf("can't get user")
		JSONResponse(w, "can't get user", http.StatusBadRequest)

		return
	}

	credential, err := p.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		p.l.Errorf(msg)

		p.deleteSessionCookie(w)
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	// If creation was successful, store the credential object
	user.AddCredential(*credential)

	err = p.userStore.Update(user)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		p.l.Errorf(msg)

		p.deleteSessionCookie(w)
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	p.sessionStore.DeleteSession(sid.Value)
	p.deleteSessionCookie(w)

	p.l.Infof("finish registration")
	JSONResponse(w, "Registration Success", http.StatusOK)
}

func (p *Passkey) beginLogin(w http.ResponseWriter, r *http.Request) {
	p.l.Infof("begin login")

	userData, err := p.parsePayload(r)
	if err != nil {
		msg := fmt.Sprintf("bad payload: %s", err.Error())
		p.l.Errorf(msg)
		JSONResponse(w, fmt.Sprintf("beginLogin failed: %s", msg), http.StatusBadRequest)

		return
	}

	// FIXME: it probably should be user.id
	user := p.userStore.Get(userData.Name)

	options, session, err := p.webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		p.l.Errorf(msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		p.deleteSessionCookie(w)

		return
	}

	// Make a session key and store the sessionData values
	t, err := p.sessionStore.GenSessionID()
	if err != nil {
		p.l.Errorf("can't generate session id: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't generate session id: %s", err.Error()), http.StatusInternalServerError)

		return
	}
	p.sessionStore.SaveSession(t, session)
	p.setSessionCookie(w, t)

	// return the options generated with the session key
	// options.publicKey contain our registration options
	JSONResponse(w, options, http.StatusOK)
}

func (p *Passkey) finishLogin(w http.ResponseWriter, r *http.Request) {
	// Get the session key from cookie
	sid, err := r.Cookie(p.cookieSettings.Name)
	if err != nil {
		p.l.Errorf("can't get session id: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't get session id: %s", err.Error()), http.StatusBadRequest)

		return
	}

	// Get the session data stored from the function above
	session, _ := p.sessionStore.GetSession(sid.Value) // FIXME: cover invalid session

	// TODO: username != user id? need to check
	// user := p.userStore.GetOrCreateUser(string(session.UserID)) // Get the user
	// FIXME: don't sure about this
	user := p.userStore.Get(string(session.UserID))

	credential, err := p.webAuthn.FinishLogin(user, *session, r)
	if err != nil {
		p.l.Errorf("can't finish login: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't finish login: %s", err.Error()), http.StatusBadRequest)

		return
	}

	// Handle credential.Authenticator.CloneWarning
	if credential.Authenticator.CloneWarning {
		p.l.Warnf("the authenticator may be cloned")
	}

	// If login was successful, update the credential object
	user.AddCredential(*credential)
	// FIXME: handle error
	p.userStore.Update(user)

	// Delete the login session data
	p.sessionStore.DeleteSession(sid.Value)
	p.deleteSessionCookie(w)

	// Add the new session cookie
	t, err := p.sessionStore.GenSessionID()
	if err != nil {
		p.l.Errorf("can't generate session id: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't generate session id: %s", err.Error()), http.StatusInternalServerError)

		return
	}

	// FIXME: we reuse the webauthn.SessionData struct, but it's not a good idea probably
	p.sessionStore.SaveSession(t, &webauthn.SessionData{
		UserID:  session.UserID,
		Expires: time.Now().Add(p.cfg.SessionMaxAge),
	})
	p.setSessionCookie(w, t)

	p.l.Infof("finish login")
	JSONResponse(w, "Login Success", http.StatusOK)
}

func (p *Passkey) parsePayload(r *http.Request) (payload, error) {
	var pld payload
	if err := json.NewDecoder(r.Body).Decode(&pld); err != nil {
		p.l.Errorf("can't decode payload: %s", err.Error())

		return payload{}, err
	}

	// user.Name is required
	if pld.Name == "" {
		return payload{}, ErrNoUsername
	}

	// if user.DisplayName is empty, use user.Name
	pld.DisplayName = cmp.Or(pld.DisplayName, pld.Name)

	return pld, nil
}

// JSONResponse sends json response
func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (p *Passkey) setSessionCookie(w http.ResponseWriter, value string) {
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

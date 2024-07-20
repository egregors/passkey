package passkey

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func (p *Passkey) beginRegistration(w http.ResponseWriter, r *http.Request) {
	p.l.Infof("begin registration")

	// TODO: i don't like this, but it's a quick solution
	//  can we actually do not use the username at all?
	username, err := getUsername(r)
	if err != nil {
		p.l.Errorf("can't get username: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't get username: %s", err.Error()), http.StatusBadRequest)

		return
	}

	user := p.userStore.GetOrCreateUser(username)

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

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    t,
		Path:     "/", // TODO: it probably shouldn't be root
		MaxAge:   registerMaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // TODO: SameSiteStrictMode maybe?
	})

	// return the options generated with the session key
	// options.publicKey contain our registration options
	JSONResponse(w, options, http.StatusOK)
}

func (p *Passkey) finishRegistration(w http.ResponseWriter, r *http.Request) {
	// Get the session key from cookie
	sid, err := r.Cookie(sessionCookieName)
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
	user := p.userStore.GetOrCreateUser(string(session.UserID)) // Get the user

	credential, err := p.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		p.l.Errorf(msg)

		deleteCookie(w, sessionCookieName)
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	// If creation was successful, store the credential object
	user.PutCredential(*credential)
	p.userStore.SaveUser(user)

	p.sessionStore.DeleteSession(sid.Value)
	deleteCookie(w, sessionCookieName)

	p.l.Infof("finish registration")
	JSONResponse(w, "Registration Success", http.StatusOK)
}

func (p *Passkey) beginLogin(w http.ResponseWriter, r *http.Request) {
	p.l.Infof("begin login")
	username, err := getUsername(r)
	if err != nil {
		p.l.Errorf("can't get user name: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't get user name: %s", err.Error()), http.StatusBadRequest)

		return
	}

	user := p.userStore.GetOrCreateUser(username)

	options, session, err := p.webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		p.l.Errorf(msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		deleteCookie(w, sessionCookieName)

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

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    t,
		Path:     "/", // TODO: it probably shouldn't be root
		MaxAge:   loginMaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // TODO: SameSiteStrictMode maybe?
	})

	// return the options generated with the session key
	// options.publicKey contain our registration options
	JSONResponse(w, options, http.StatusOK)
}

func (p *Passkey) finishLogin(w http.ResponseWriter, r *http.Request) {
	// Get the session key from cookie
	sid, err := r.Cookie(sessionCookieName)
	if err != nil {
		p.l.Errorf("can't get session id: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't get session id: %s", err.Error()), http.StatusBadRequest)

		return
	}

	// Get the session data stored from the function above
	session, _ := p.sessionStore.GetSession(sid.Value) // FIXME: cover invalid session

	// TODO: username != user id? need to check
	user := p.userStore.GetOrCreateUser(string(session.UserID)) // Get the user

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
	user.PutCredential(*credential)
	p.userStore.SaveUser(user)

	// Delete the login session data
	p.sessionStore.DeleteSession(sid.Value)
	deleteCookie(w, sessionCookieName)

	// Add the new session cookie
	t, err := p.sessionStore.GenSessionID()
	if err != nil {
		p.l.Errorf("can't generate session id: %s", err.Error())
		JSONResponse(w, fmt.Sprintf("can't generate session id: %s", err.Error()), http.StatusInternalServerError)

		return
	}

	p.sessionStore.SaveSession(t, &webauthn.SessionData{
		Expires: time.Now().Add(time.Hour),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    t,
		Path:     "/",
		MaxAge:   int(p.sessionMaxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // TODO: SameSiteStrictMode maybe?
	})

	p.l.Infof("finish login")
	JSONResponse(w, "Login Success", http.StatusOK)
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

// deleteCookie deletes a cookie
func deleteCookie(w http.ResponseWriter, name string) { //nolint:unparam // it's ok here
	http.SetCookie(w, &http.Cookie{
		Name:    name,
		Value:   "",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
}

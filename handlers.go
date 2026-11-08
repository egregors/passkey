package passkey

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	maxRequestBodyBytes = 1 << 20 // 1 MiB, including WebAuthn attestation responses.
	maxUsernameBytes    = 256
)

// limitRequestBody checks the entire body before handlers can modify sessions or users.
// Buffering also covers oversized trailing data that a decoder might otherwise ignore.
func limitRequestBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limited := http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		defer limited.Close()

		body, err := io.ReadAll(limited)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				JSONResponse(w, "request body exceeds 1 MiB", http.StatusRequestEntityTooLarge)
			} else {
				JSONResponse(w, "can't read request body", http.StatusBadRequest)
			}
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(body))
		next(w, r)
	}
}

func genUserID() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("can't generate user id: %w", err)
	}

	return b, nil
}

func (p *Passkey) beginRegistration(w http.ResponseWriter, r *http.Request) {
	p.log.Infof(">>> begin registration")

	var err error
	defer func() {
		if err != nil {
			p.log.Errorf("%s", err.Error())
			writeHandlerError(w, err)
			p.log.Debugf("begin registration: done with error")
		}
	}()

	p.log.Debugf("got request")
	username, err := getUsername(r)
	if err != nil {
		err = fmt.Errorf("can't get username: %w", err)

		return
	}
	p.log.Debugf("got username: %s", username)

	if existingUser, getErr := p.userStore.GetByName(username); getErr == nil && existingUser != nil {
		err = fmt.Errorf("%w: %s", ErrUserAlreadyExists, username)

		return
	} else if getErr != nil && !errors.Is(getErr, ErrUserNotFound) {
		err = fmt.Errorf("can't check user: %w", getErr)

		return
	}

	userID, err := genUserID()
	if err != nil {
		err = fmt.Errorf("can't generate user id: %w", err)

		return
	}

	user := &transientUser{
		id:   userID,
		name: username,
	}

	p.log.Debugf("try to get options from webauthn")
	options, session, err := p.webAuthn.BeginRegistration(user)
	if err != nil {
		err = fmt.Errorf("can't begin registration: %w", err)

		return
	}
	p.log.Debugf("got options")

	p.log.Debugf("try to save session")
	expires := time.Now().Add(p.cookieSettings.registrationSessionMaxAge)
	if !session.Expires.IsZero() && session.Expires.Before(expires) {
		expires = session.Expires
	} else {
		session.Expires = expires
	}

	t, err := p.registrationSessionStore.Create(RegistrationSessionData{
		Username: username,
		Session:  *session,
		Expires:  expires,
	})
	if err != nil {
		err = fmt.Errorf("can't save session: %w", err)

		return
	}
	p.log.Debugf("session saved")

	p.log.Debugf("setting cookie")
	p.setRegistrationSessionCookie(w, t)

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
			p.deleteSessionCookie(p.cookieSettings.registrationSessionName, w)
			p.log.Errorf("%s", err.Error())
			writeHandlerError(w, err)
			p.log.Debugf("cleaned up session cookie")
			p.log.Debugf("<<< finish registration: done with error")
		}
	}()

	// Get the session key from cookie
	p.log.Debugf("getting session id from cookie")
	sid, err := r.Cookie(p.cookieSettings.registrationSessionName)
	if err != nil {
		err = fmt.Errorf("can't get session id: %w", err)

		return
	}
	p.log.Debugf("got session id")

	// Atomically consume registration session data
	p.log.Debugf("try to consume session data")
	regData, ok := p.registrationSessionStore.Consume(sid.Value)
	if !ok || regData == nil {
		err = fmt.Errorf("can't get session data")

		return
	}
	p.log.Debugf("got session data")

	if !regData.Expires.IsZero() && regData.Expires.Before(time.Now()) {
		err = fmt.Errorf("registration session has expired")

		return
	}

	user := &transientUser{
		id:   regData.Session.UserID,
		name: regData.Username,
	}

	p.log.Debugf("try to get credential from webauthn")
	credential, err := p.webAuthn.FinishRegistration(user, regData.Session, r)
	if err != nil {
		err = fmt.Errorf("can't finish registration: %w", err)

		return
	}
	p.log.Debugf("got credential")

	p.log.Debugf("try to create user")
	_, err = p.userStore.Create(NewUser{
		Username:   regData.Username,
		UserID:     regData.Session.UserID,
		Credential: *credential,
	})
	if err != nil {
		err = fmt.Errorf("can't create user: %w", err)

		return
	}
	p.log.Debugf("user created")

	p.deleteSessionCookie(p.cookieSettings.registrationSessionName, w)
	JSONResponse(w, "Registration Success", http.StatusOK)

	p.log.Infof("<<< finish registration: done")
}

func (p *Passkey) beginLogin(w http.ResponseWriter, r *http.Request) {
	p.log.Infof(">>> begin login")

	var err error
	defer func() {
		if err != nil {
			p.log.Errorf("%s", err.Error())
			writeHandlerError(w, err)
			p.log.Debugf("<<< begin login: done with error")
		}
	}()

	p.log.Debugf("got request")
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
		p.deleteSessionCookie(p.cookieSettings.loginSessionName, w)

		return
	}
	p.log.Debugf("got options")

	p.log.Debugf("try to save session")
	expires := time.Now().Add(p.cookieSettings.loginSessionMaxAge)
	if session.Expires.IsZero() || session.Expires.After(expires) {
		session.Expires = expires
	}
	t, err := p.loginSessionStore.Create(*session)
	if err != nil {
		err = fmt.Errorf("can't save session: %w", err)

		return
	}
	p.log.Debugf("session saved")

	p.log.Debugf("setting cookie")
	p.setLoginSessionCookie(w, t)

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
			writeHandlerError(w, err)
			p.log.Debugf("<<< finish login: done with error")
		}
	}()

	// Get the session key from cookie
	p.log.Debugf("getting session id from cookie")
	sid, err := r.Cookie(p.cookieSettings.loginSessionName)
	if err != nil {
		err = fmt.Errorf("can't get session id: %w", err)

		return
	}
	p.log.Debugf("got session")

	// Every attempt with a login cookie ends this ceremony, even if verification fails.
	p.deleteSessionCookie(p.cookieSettings.loginSessionName, w)

	// Consume before verification so concurrent requests cannot reuse the challenge.
	p.log.Debugf("try to consume session data")
	session, ok := p.loginSessionStore.Consume(sid.Value)
	if !ok || session == nil {
		err = fmt.Errorf("can't get session data")

		return
	}
	p.log.Debugf("got session data")

	if session.Expires.IsZero() || !time.Now().Before(session.Expires) {
		err = fmt.Errorf("login session has expired")

		return
	}

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

	err = p.userStore.UpdateCredential(session.UserID, *credential)
	if err != nil {
		err = fmt.Errorf("can't update credential: %w", err)

		return
	}
	p.log.Debugf("credential updated")

	p.log.Debugf("try to save user session")
	t, err := p.userSessionStore.Create(UserSessionData{
		Purpose: userSessionPurpose,
		UserID:  session.UserID,
		Expires: time.Now().Add(p.cookieSettings.userSessionMaxAge),
	})
	if err != nil {
		err = fmt.Errorf("can't save user session: %w", err)

		return
	}
	p.log.Debugf("session saved")

	p.log.Debugf("setting cookie")
	p.setUserSessionCookie(w, t)

	JSONResponse(w, "Login Success", http.StatusOK)

	p.log.Infof("<<< finish login")
}

func (p *Passkey) setLoginSessionCookie(w http.ResponseWriter, value string) {
	p.setSessionCookie(
		w,
		p.cookieSettings.loginSessionName,
		value,
		p.cookieSettings.loginSessionMaxAge,
	)
}

func (p *Passkey) setRegistrationSessionCookie(w http.ResponseWriter, value string) {
	p.setSessionCookie(
		w,
		p.cookieSettings.registrationSessionName,
		value,
		p.cookieSettings.registrationSessionMaxAge,
	)
}

func (p *Passkey) setUserSessionCookie(w http.ResponseWriter, value string) {
	p.setSessionCookie(
		w,
		p.cookieSettings.userSessionName,
		value,
		p.cookieSettings.userSessionMaxAge,
	)
}

func (p *Passkey) setSessionCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	// Secure is enabled by default and can only be disabled explicitly with
	// WithInsecureCookie for local development. HttpOnly and SameSite are
	// initialized to secure values in setupCookieSettings.
	//nolint:gosec // G124 cannot infer the secure defaults behind cookieSettings.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     p.cookieSettings.Path,
		MaxAge:   int(maxAge.Seconds()),
		Secure:   p.cookieSettings.Secure,
		HttpOnly: p.cookieSettings.HttpOnly,
		SameSite: p.cookieSettings.SameSite,
	})
}

// Logout deletes session from session store and deletes session cookie
func (p *Passkey) Logout(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie(p.cookieSettings.userSessionName)
	if err != nil {
		p.log.Errorf("can't get session cookie: %s", err.Error())

		return
	}

	p.userSessionStore.Delete(sid.Value)
	p.deleteSessionCookie(p.cookieSettings.userSessionName, w)
}

// deleteSessionCookie deletes a cookie
func (p *Passkey) deleteSessionCookie(name string, w http.ResponseWriter) { //nolint:unparam // it's ok here
	// Use the same scope and security attributes as the original cookie so the
	// browser reliably expires that cookie instead of creating a second one.
	//nolint:gosec // G124 cannot infer the secure defaults behind cookieSettings.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     p.cookieSettings.Path,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   p.cookieSettings.Secure,
		HttpOnly: p.cookieSettings.HttpOnly,
		SameSite: p.cookieSettings.SameSite,
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
	if len(u.Username) > maxUsernameBytes {
		return "", ErrUsernameTooLong
	}

	return u.Username, nil
}

func writeHandlerError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrSessionStoreFull) {
		JSONResponse(w, ErrSessionStoreFull.Error(), http.StatusServiceUnavailable)
		return
	}
	JSONResponse(w, err.Error(), http.StatusBadRequest)
}

// JSONResponse sends json response
func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

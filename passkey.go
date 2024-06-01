package passkey

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	pathRegisterBegin  = "/passkey/registerBegin"
	pathRegisterFinish = "/passkey/registerFinish"
	pathLoginBegin     = "/passkey/loginBegin"
	pathLoginFinish    = "/passkey/loginFinish"
	pathStatic         = "/passkey/static"

	registerMaxAge = 3600
	loginMaxAge    = 3600

	sessionCookieName = "sid"
)

type Config struct {
	WebauthnConfig *webauthn.Config
	UserStore
	SessionStore
	SessionMaxAge int
}

type Passkey struct {
	cfg Config

	webAuthn *webauthn.WebAuthn

	userStore    UserStore
	sessionStore SessionStore

	sessionMaxAge int

	mux *http.ServeMux

	l Logger
}

func New(cfg Config, opts ...Option) (*Passkey, error) {
	p := &Passkey{
		cfg:           cfg,
		mux:           http.NewServeMux(),
		sessionMaxAge: cfg.SessionMaxAge,
	}

	// TODO: setup default options
	for _, opt := range opts {
		opt(p)
	}

	p.setupRoutes()

	err := p.setupWebAuthn()
	if err != nil {
		return nil, errors.New("can't create webauthn: " + err.Error())
	}

	return p, nil
}

func (p *Passkey) setupWebAuthn() error {
	webAuthn, err := webauthn.New(p.cfg.WebauthnConfig)
	if err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		p.l.Errorf("can't create webauthn: %s", err.Error())
		return err
	}

	p.webAuthn = webAuthn

	return nil
}

func (p *Passkey) setupRoutes() (mux *http.ServeMux) {
	mux.HandleFunc(pathRegisterBegin, p.beginRegistration)
	mux.HandleFunc(pathRegisterFinish, p.finishRegistration)
	mux.HandleFunc(pathLoginBegin, p.beginLogin)
	mux.HandleFunc(pathLoginFinish, p.finishLogin)
	// TODO: fix directory path
	mux.Handle(pathStatic, http.FileServer(http.Dir("./web")))

	return mux
}

func (p *Passkey) Routes() *http.ServeMux {
	return p.mux
}

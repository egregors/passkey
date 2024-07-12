package passkey

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	pathRegisterBegin  = "/passkey/registerBegin"
	pathRegisterFinish = "/passkey/registerFinish"
	pathLoginBegin     = "/passkey/loginBegin"
	pathLoginFinish    = "/passkey/loginFinish"

	registerMaxAge = 3600
	loginMaxAge    = 3600

	sessionCookieName = "sid"
)

type Config struct {
	WebauthnConfig *webauthn.Config
	UserStore
	SessionStore
	SessionMaxAge time.Duration
}

type Passkey struct {
	cfg Config

	webAuthn *webauthn.WebAuthn

	userStore    UserStore
	sessionStore SessionStore

	sessionMaxAge time.Duration

	mux       *http.ServeMux
	staticMux *http.ServeMux

	l Logger
}

func New(cfg Config, opts ...Option) (*Passkey, error) {
	p := &Passkey{
		cfg: cfg,

		userStore:     cfg.UserStore,
		sessionStore:  cfg.SessionStore,
		sessionMaxAge: cfg.SessionMaxAge,

		mux:       http.NewServeMux(),
		staticMux: http.NewServeMux(),
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
	p.mux.HandleFunc(pathRegisterBegin, p.beginRegistration)
	p.mux.HandleFunc(pathRegisterFinish, p.finishRegistration)
	p.mux.HandleFunc(pathLoginBegin, p.beginLogin)
	p.mux.HandleFunc(pathLoginFinish, p.finishLogin)

	p.staticMux.Handle("/", http.FileServer(http.Dir("./static")))

	return mux
}

func (p *Passkey) MountRoutes(mux *http.ServeMux, path string) {
	mux.Handle(path, http.StripPrefix(path[:len(path)-1], p.mux))
}

func (p *Passkey) MountStaticRoutes(mux *http.ServeMux, path string) {
	mux.Handle(path, http.StripPrefix(path[:len(path)-1], p.staticMux))
}

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

	defaultSessionCookieName = "sid"
	defaultCookieMaxAge      = 60 * time.Minute
)

type Config struct {
	WebauthnConfig *webauthn.Config
	UserStore
	SessionStore
	SessionMaxAge time.Duration
}

type CookieSettings struct {
	Name     string
	Path     string
	MaxAge   time.Duration
	Secure   bool
	HttpOnly bool //nolint:stylecheck // naming from http.Cookie
	SameSite http.SameSite
}

type Passkey struct {
	cfg Config

	webAuthn *webauthn.WebAuthn

	userStore    UserStore
	sessionStore SessionStore

	mux       *http.ServeMux
	staticMux *http.ServeMux

	l              Logger
	cookieSettings CookieSettings
}

// New creates new Passkey instance
func New(cfg Config, opts ...Option) (*Passkey, error) {
	p := &Passkey{
		cfg: cfg,

		userStore:    cfg.UserStore,
		sessionStore: cfg.SessionStore,

		mux:       http.NewServeMux(),
		staticMux: http.NewServeMux(),

		cookieSettings: CookieSettings{
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	p.setupOptions(opts)
	p.setupRoutes()

	err := p.setupWebAuthn()
	if err != nil {
		return nil, errors.New("can't create webauthn: " + err.Error())
	}

	p.raiseWarnings()

	return p, nil
}

func (p *Passkey) setupOptions(opts []Option) {
	setupDefaultOptions(p)
	for _, opts := range opts {
		opts(p)
	}
}

func setupDefaultOptions(p *Passkey) {
	defaultOpts := []Option{
		WithLogger(&NullLogger{}),
		WithSessionCookieName(defaultSessionCookieName),
		WithCookieMaxAge(defaultCookieMaxAge),
	}

	for _, opt := range defaultOpts {
		opt(p)
	}
}

func (p *Passkey) raiseWarnings() {
	if p.cfg.SessionMaxAge == 0 {
		p.l.Warnf("session max age is not set")
	}

	if !p.cookieSettings.Secure {
		p.l.Warnf("cookie is not secure!")
	}
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

func (p *Passkey) setupRoutes() {
	p.mux.HandleFunc(pathRegisterBegin, p.beginRegistration)
	p.mux.HandleFunc(pathRegisterFinish, p.finishRegistration)
	p.mux.HandleFunc(pathLoginBegin, p.beginLogin)
	p.mux.HandleFunc(pathLoginFinish, p.finishLogin)

	p.staticMux.Handle("/", http.FileServer(http.Dir("./static")))
}

// MountRoutes mounts passkey routes to mux
func (p *Passkey) MountRoutes(mux *http.ServeMux, path string) {
	mux.Handle(path, http.StripPrefix(path[:len(path)-1], p.mux))
}

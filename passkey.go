package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	logger "github.com/egregors/passkey/log"
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
	AuthSessionStore  SessionStore[webauthn.SessionData]
	UserSessionStore  SessionStore[UserSessionData]
	UserSessionMaxAge time.Duration
}

type UserSessionData struct {
	UserID  []byte
	Expires time.Time
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

	userStore        UserStore
	authSessionStore SessionStore[webauthn.SessionData]
	userSessionStore SessionStore[UserSessionData]

	mux       *http.ServeMux
	staticMux *http.ServeMux

	log            Logger
	cookieSettings CookieSettings
}

// New creates new Passkey instance
func New(cfg Config, opts ...Option) (*Passkey, error) {
	p := &Passkey{
		cfg: cfg,

		userStore:        cfg.UserStore,
		authSessionStore: cfg.AuthSessionStore,
		userSessionStore: cfg.UserSessionStore,

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
		return nil, fmt.Errorf("can't create webauthn: %w", err)
	}

	if err := p.must(); err != nil {
		return nil, fmt.Errorf("invalid cfg: %w", err)
	}
	p.raiseWarnings()

	return p, nil
}

func (p *Passkey) must() error {
	return mustNotNil(map[string]any{
		"userStore":        p.userStore,
		"authSessionStore": p.authSessionStore,
		"userSessionStore": p.userSessionStore,
	})
}

func mustNotNil(nillable map[string]any) error {
	for k, v := range nillable {
		if v == nil {
			return fmt.Errorf("%s can't be nil", k)
		}
	}

	return nil
}

func (p *Passkey) setupOptions(opts []Option) {
	setupDefaultOptions(p)
	for _, opt := range opts {
		opt(p)
	}
}

func setupDefaultOptions(p *Passkey) {
	defaultOpts := []Option{
		WithLogger(logger.NewLogger()),
		WithSessionCookieName(defaultSessionCookieName),
		WithCookieMaxAge(defaultCookieMaxAge),
	}

	for _, opt := range defaultOpts {
		opt(p)
	}
}

func (p *Passkey) raiseWarnings() {
	if p.cfg.UserSessionMaxAge == 0 {
		p.log.Warnf("session max age is not set")
	}

	if !p.cookieSettings.Secure {
		p.log.Warnf("cookie is not secure!")
	}
}

func (p *Passkey) setupWebAuthn() error {
	webAuthn, err := webauthn.New(p.cfg.WebauthnConfig)
	if err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		p.log.Errorf("can't create webauthn: %s", err.Error())
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

func defaultSessionIDGenerator() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

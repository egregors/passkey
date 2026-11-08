package passkey

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/egregors/passkey/deps"
	"github.com/go-webauthn/webauthn/webauthn"

	logger "github.com/egregors/passkey/log"
)

const (
	pathRegisterBegin  = "/passkey/registerBegin"
	pathRegisterFinish = "/passkey/registerFinish"
	pathLoginBegin     = "/passkey/loginBegin"
	pathLoginFinish    = "/passkey/loginFinish"

	defaultSessionNamePrefix         = "pk"
	defaultLoginSessionName          = "lsid"
	defaultRegistrationSessionName   = "rsid"
	defaultUserSessionName           = "usid"
	defaultLoginSessionMaxAge        = 5 * time.Minute
	defaultRegistrationSessionMaxAge = 5 * time.Minute
	defaultUserSessionMaxAge         = 60 * time.Minute
	userSessionPurpose               = "passkey:user-session:v1"
)

type Config struct {
	WebauthnConfig *webauthn.Config
	UserStore
	LoginSessionStore        SessionStore[webauthn.SessionData]
	RegistrationSessionStore SessionStore[RegistrationSessionData]
	UserSessionStore         SessionStore[UserSessionData]
}

type RegistrationSessionData struct {
	Username string
	Session  webauthn.SessionData
	Expires  time.Time
}

type UserSessionData struct {
	Purpose string
	UserID  []byte
	Expires time.Time
}

type CookieSettings struct {
	Path                      string
	loginSessionName          string
	registrationSessionName   string
	userSessionName           string
	loginSessionMaxAge        time.Duration
	registrationSessionMaxAge time.Duration
	userSessionMaxAge         time.Duration
	Secure                    bool
	HttpOnly                  bool //nolint:revive // naming from http.Cookie
	SameSite                  http.SameSite
}

type Passkey struct {
	cfg Config

	webAuthn deps.WebAuthnInterface

	userStore                UserStore
	loginSessionStore        SessionStore[webauthn.SessionData]
	registrationSessionStore SessionStore[RegistrationSessionData]
	userSessionStore         SessionStore[UserSessionData]

	mux       *http.ServeMux
	staticMux *http.ServeMux

	log            Logger
	cookieSettings CookieSettings
}

// New creates new Passkey instance
func New(cfg Config, opts ...Option) (*Passkey, error) {
	p := &Passkey{
		cfg: cfg,

		userStore:                cfg.UserStore,
		loginSessionStore:        cfg.LoginSessionStore,
		registrationSessionStore: cfg.RegistrationSessionStore,
		userSessionStore:         cfg.UserSessionStore,

		mux:       http.NewServeMux(),
		staticMux: http.NewServeMux(),
	}

	p.setupCookieSettings()
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
	for _, name := range []string{p.cookieSettings.loginSessionName, p.cookieSettings.registrationSessionName, p.cookieSettings.userSessionName} {
		//nolint:gosec // Name validation only; this cookie is never sent.
		if err := (&http.Cookie{Name: name}).Valid(); err != nil {
			return fmt.Errorf("invalid cookie name: %w", err)
		}
		lower := strings.ToLower(name)
		if !p.cookieSettings.Secure && (strings.HasPrefix(lower, "__host-") || strings.HasPrefix(lower, "__secure-")) {
			return fmt.Errorf("reserved cookie prefix requires secure cookies")
		}
	}
	return mustNotNil(map[string]any{
		"userStore":                p.userStore,
		"loginSessionStore":        p.loginSessionStore,
		"registrationSessionStore": p.registrationSessionStore,
		"userSessionStore":         p.userSessionStore,
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
	if p.cookieSettings.Secure {
		p.cookieSettings.loginSessionName = "__Host-" + p.cookieSettings.loginSessionName
		p.cookieSettings.registrationSessionName = "__Host-" + p.cookieSettings.registrationSessionName
		p.cookieSettings.userSessionName = "__Host-" + p.cookieSettings.userSessionName
	}
}

func setupDefaultOptions(p *Passkey) {
	defaultOpts := []Option{
		WithLogger(logger.NewLogger()),
		WithSessionCookieNamePrefix(defaultSessionNamePrefix),
		WithUserSessionMaxAge(defaultUserSessionMaxAge),
	}

	for _, opt := range defaultOpts {
		opt(p)
	}
}

func (p *Passkey) raiseWarnings() {
	if p.cookieSettings.userSessionMaxAge == 0 {
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
	p.mux.HandleFunc(pathRegisterBegin, p.mutationHandler(limitRequestBody(p.beginRegistration)))
	p.mux.HandleFunc(pathRegisterFinish, p.mutationHandler(limitRequestBody(p.finishRegistration)))
	p.mux.HandleFunc(pathLoginBegin, p.mutationHandler(limitRequestBody(p.beginLogin)))
	p.mux.HandleFunc(pathLoginFinish, p.mutationHandler(limitRequestBody(p.finishLogin)))

	p.staticMux.Handle("/", http.FileServer(http.Dir("./static")))
}

// MountRoutes mounts passkey routes to mux
func (p *Passkey) MountRoutes(mux *http.ServeMux, path string) {
	mux.Handle(path, http.StripPrefix(path[:len(path)-1], p.mux))
}

func (p *Passkey) setupCookieSettings() {
	p.cookieSettings = CookieSettings{
		Path:                      "/",
		loginSessionName:          defaultLoginSessionName,
		registrationSessionName:   defaultRegistrationSessionName,
		userSessionName:           defaultUserSessionName,
		loginSessionMaxAge:        defaultLoginSessionMaxAge,
		registrationSessionMaxAge: defaultRegistrationSessionMaxAge,
		userSessionMaxAge:         defaultUserSessionMaxAge,
		Secure:                    true,
		HttpOnly:                  true,
		SameSite:                  http.SameSiteLaxMode,
	}
}

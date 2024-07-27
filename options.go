package passkey

import "time"

type Option func(*Passkey)

// WithLogger sets the logger for the passkey instance.
func WithLogger(l Logger) Option {
	return func(p *Passkey) {
		if l != nil {
			p.l = l
		}
	}
}

// WithInsecureCookie sets Cookie.Secure to false. This is useful for development. Do not use in production.
func WithInsecureCookie() Option {
	return func(p *Passkey) {
		p.cookieSettings.Secure = false
	}
}

// WithSessionCookieName sets the name of the session cookie.
func WithSessionCookieName(name string) Option {
	return func(p *Passkey) {
		if name != "" {
			p.cookieSettings.Name = name
		}
	}
}

// WithCookieMaxAge sets the max age of the session cookie.
func WithCookieMaxAge(maxAge time.Duration) Option {
	return func(p *Passkey) {
		if maxAge > 0 {
			p.cookieSettings.MaxAge = maxAge
		}
	}
}

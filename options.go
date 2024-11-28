package passkey

import (
	"fmt"
	"strings"
	"time"
)

type Option func(*Passkey)

// WithLogger sets the logger for the passkey instance.
func WithLogger(l Logger) Option {
	return func(p *Passkey) {
		if l != nil {
			p.log = l
		}
	}
}

// WithInsecureCookie sets Cookie.Secure to false. This is useful for development. Do not use in production.
func WithInsecureCookie() Option {
	return func(p *Passkey) {
		p.cookieSettings.Secure = false
	}
}

// WithSessionCookieNamePrefix sets custom prefix for names of the session cookies instead of default.
func WithSessionCookieNamePrefix(prefix string) Option {
	return func(p *Passkey) {
		if prefix != "" {
			p.cookieSettings.authSessionName = camelCaseConcat(
				prefix,
				strings.TrimPrefix(p.cookieSettings.authSessionName, defaultSessionNamePrefix),
			)
			p.cookieSettings.userSessionName = camelCaseConcat(
				prefix,
				strings.TrimPrefix(p.cookieSettings.userSessionName, defaultSessionNamePrefix),
			)
		}
	}
}

// WithUserSessionMaxAge sets the max age of the user session cookie.
func WithUserSessionMaxAge(maxAge time.Duration) Option {
	return func(p *Passkey) {
		if maxAge > 0 {
			p.cookieSettings.userSessionMaxAge = maxAge
		}
	}
}

func camelCaseConcat(ws ...string) string {
	if len(ws) == 0 {
		return ""
	}
	if len(ws) == 1 {
		return ws[0]
	}

	invalidChars := []string{" ", "\t", "\n", "\r"}

	sb := strings.Builder{}
	sb.WriteString(strings.ToLower(ws[0]))

	for i := 1; i < len(ws); i++ {
		w := ws[i]

		for _, ch := range invalidChars {
			w = strings.ReplaceAll(w, ch, "")
		}

		if w == "" {
			continue
		}

		sb.WriteString(
			fmt.Sprintf(
				"%s%s",
				string(strings.ToUpper(w)[0]),
				strings.ToLower(w)[1:],
			))
	}

	return sb.String()
}

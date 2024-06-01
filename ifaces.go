package passkey

import "github.com/go-webauthn/webauthn/webauthn"

type Logger interface {
	Errorf(format string, v ...any)
	Debugf(format string, v ...any)
	Infof(format string, v ...any)
	Warnf(format string, v ...any)
}

type Metrics interface {
	Count(name string, value int64)
	Increment(name string)
}

type User interface {
	webauthn.User
	AddCredential(*webauthn.Credential)
	UpdateCredential(*webauthn.Credential)
}

type UserStore interface {
	GetOrCreateUser(userName string) User
	SaveUser(User)
}

type SessionStore interface {
	GenSessionID() (string, error)
	GetSession(token string) (webauthn.SessionData, bool)
	SaveSession(token string, data webauthn.SessionData)
	DeleteSession(token string)
}

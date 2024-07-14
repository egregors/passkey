package passkey

import "github.com/go-webauthn/webauthn/webauthn"

type Logger interface {
	Errorf(format string, v ...any)
	Debugf(format string, v ...any)
	Infof(format string, v ...any)
	Warnf(format string, v ...any)
}

type User interface {
	webauthn.User
	PutCredential(webauthn.Credential)
}

type UserStore interface {
	GetOrCreateUser(userName string) User
	SaveUser(User)
}

type SessionStore interface {
	GenSessionID() (string, error)
	GetSession(token string) (*webauthn.SessionData, bool)
	SaveSession(token string, data *webauthn.SessionData)
	DeleteSession(token string)
}

// NullLogger is a logger that does nothing
type NullLogger struct{}

func (n NullLogger) Errorf(_ string, _ ...any) {}
func (n NullLogger) Debugf(_ string, _ ...any) {}
func (n NullLogger) Infof(_ string, _ ...any)  {}
func (n NullLogger) Warnf(_ string, _ ...any)  {}

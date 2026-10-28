package passkey

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// Logger is a simple logger interface
type Logger interface {
	Errorf(format string, v ...any)
	Debugf(format string, v ...any)
	Infof(format string, v ...any)
	Warnf(format string, v ...any)
}

// User is a user with webauthn credentials
type User interface {
	webauthn.User
	PutCredential(webauthn.Credential)
}

// UserStore is a persistent storage for users and credentials
type UserStore interface {
	// Create must atomically insert a new user with a new WebAuthn ID and no
	// credentials. If the username exists, return ErrUserAlreadyExists.
	// Never return an existing user or use an upsert for public registration.
	Create(username string) (User, error)
	Update(User) error

	Get(userID []byte) (User, error)
	GetByName(username string) (User, error)
}

// SessionStore is a storage for session data
type SessionStore[T webauthn.SessionData | UserSessionData] interface {
	Create(data T) (string, error)
	Delete(token string)

	Get(token string) (*T, bool)
}

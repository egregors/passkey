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

// NewUser contains the data required to create a new registered user.
type NewUser struct {
	Username   string
	UserID     []byte
	Credential webauthn.Credential
}

// UserStore is a persistent storage for users and credentials.
// Implementations of Create must atomically persist the account and its initial credential,
// preserving the exact UserID handle, and enforcing unique username and user ID.
type UserStore interface {
	Create(u NewUser) (User, error)
	Update(User) error

	Get(userID []byte) (User, error)
	GetByName(username string) (User, error)
}

// SessionStore is a storage for session data.
// Consume must atomically retrieve and delete the session identified by token to prevent replay.
// Login and registration handlers consume ceremony sessions before verification, including failed attempts.
// Implementations must also clean up expired records to reclaim storage; handlers enforce expiration independently.
type SessionStore[T any] interface {
	Create(data T) (string, error)
	Delete(token string)
	Get(token string) (*T, bool)
	Consume(token string) (*T, bool)
}

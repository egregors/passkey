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
// Reads and Create return detached snapshots, including credential byte slices.
type UserStore interface {
	Create(u NewUser) (User, error)
	// UpdateCredential atomically updates an existing credential's authentication state.
	// Preserve registration data and other credentials; ignore updates with older counters.
	// Retain previously observed clone warnings.
	// Unknown users and credentials return ErrUserNotFound and ErrCredentialNotFound respectively.
	UpdateCredential(userID []byte, credential webauthn.Credential) error

	Get(userID []byte) (User, error)
	GetByName(username string) (User, error)
}

// SessionStore is a storage for session data.
// Stores must use distinct key namespaces for each session type and application/tenant scope.
// Create must return a unique, cryptographically random token with at least 128 bits of entropy.
// Serialization must preserve all fields, including Purpose; adapters must not synthesize missing fields.
// Consume must atomically retrieve and delete the session identified by token to prevent replay.
// Login and registration handlers consume ceremony sessions before verification, including failed attempts.
// Stores must bound retained records and reclaim expired entries before rejecting new sessions.
// Create returns ErrSessionStoreFull when capacity is exhausted; handlers enforce expiration independently.
type SessionStore[T any] interface {
	Create(data T) (string, error)
	Delete(token string)
	Get(token string) (*T, bool)
	Consume(token string) (*T, bool)
}

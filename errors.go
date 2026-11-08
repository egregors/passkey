package passkey

import "fmt"

var (
	ErrNoUsername         = fmt.Errorf("no username provided")
	ErrUsernameTooLong    = fmt.Errorf("username exceeds 256 bytes")
	ErrUserNotFound       = fmt.Errorf("user not found")
	ErrCredentialNotFound = fmt.Errorf("credential not found")
	ErrUserAlreadyExists  = fmt.Errorf("user already exists")
	ErrSessionStoreFull   = fmt.Errorf("session storage is full")
)

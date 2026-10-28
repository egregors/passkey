package passkey

import "fmt"

var (
	ErrNoUsername = fmt.Errorf("no username provided")
	// ErrUserAlreadyExists means public registration cannot enroll this user.
	ErrUserAlreadyExists = fmt.Errorf("user already exists")
)

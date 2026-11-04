package passkey

import "fmt"

var (
	ErrNoUsername        = fmt.Errorf("no username provided")
	ErrUserNotFound      = fmt.Errorf("user not found")
	ErrUserAlreadyExists = fmt.Errorf("user already exists")
)

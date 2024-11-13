package passkey

import "fmt"

var (
	ErrNoUsername = fmt.Errorf("no username provided: missing key 'name'")
)

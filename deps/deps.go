package deps

import (
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	. "github.com/go-webauthn/webauthn/webauthn" //nolint:staticcheck,revive // naming from webauthn.WebAuthn
)

type WebAuthnInterface interface {
	BeginRegistration(user User, opts ...RegistrationOption) (creation *protocol.CredentialCreation, session *SessionData, err error)
	FinishRegistration(user User, session SessionData, response *http.Request) (*Credential, error)
	BeginLogin(user User, opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error)
	FinishLogin(user User, session SessionData, response *http.Request) (*Credential, error)
}

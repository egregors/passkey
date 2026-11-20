<div align="center">
    <h1>🔑 passkey</h1>

`passkey` is a Go library for implementing WebAuthn services

[![Go Reference](https://pkg.go.dev/badge/github.com/egregors/passkey.svg)](https://pkg.go.dev/github.com/egregors/passkey)
[![Go Report Card](https://goreportcard.com/badge/github.com/egregors/passkey)](https://goreportcard.com/report/github.com/egregors/passkey)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

---

`passkey` handles WebAuthn registration, login ceremonies, and session authentication for Go HTTP services with pluggable storage and context-aware middleware. Built on top of [go-webauthn](https://github.com/go-webauthn/webauthn).

## Features

- **WebAuthn Ceremonies**: Handlers for passkey registration and login flows.
- **Session Management**: Isolated, bounded session stores for registration, login, and authenticated user sessions.
- **Authentication Middleware**: Standard HTTP middleware to protect routes and inject authenticated user IDs into context.
- **Pluggable Storage**: Interfaces for account persistence and session caching.

> [!NOTE]
> In general, this library is built on top of two open-source solutions:
> * Golang WebAuthn Library – https://github.com/go-webauthn/webauthn
> * JS/TS SimpleWebAuthn client – https://github.com/MasterKale/SimpleWebAuthn

Used in project:
![Static Badge](https://img.shields.io/badge/Go_WebAuthn-v0.17.4-green)
![Static Badge](https://img.shields.io/badge/TS%5CJS%20SimpleWebAuthn-v13.3.0-green)

Actual versions:
![GitHub Release](https://img.shields.io/github/v/release/go-webauthn/webauthn?label=Go%20WebAuthn)
![npm](https://img.shields.io/npm/v/%40simplewebauthn%2Fbrowser?label=TS%5CJS%20SimpleWebAuthn)

## Installation

Requires Go 1.25 or newer.

```bash
go get github.com/egregors/passkey
```

## Usage

### 1. Implement storage

Implement [`UserStore`, `User`, and `SessionStore[T]`](ifaces.go). Passkey uses one user store and three typed session stores:

| Store | Record Type | Purpose | Methods |
|---|---|---|---|
| `UserStore` | `passkey.User` | Accounts and registered credentials | `Create`, `UpdateCredential`, `Get`, `GetByName` |
| `LoginSessionStore` | `webauthn.SessionData` | Pending login challenges | `Create`, `Delete`, `Get`, `Consume` |
| `RegistrationSessionStore` | `passkey.RegistrationSessionData` | Pending registration challenges | `Create`, `Delete`, `Get`, `Consume` |
| `UserSessionStore` | `passkey.UserSessionData` | Authenticated user sessions | `Create`, `Delete`, `Get`, `Consume` |

- `UserStore.Create` atomically persists the account and initial credential, returning `ErrUserAlreadyExists` on conflicts. Lookups return `ErrUserNotFound` for missing users.
- `UserStore.UpdateCredential` atomically updates a credential's authentication state (signature counters, clone warnings).
- `SessionStore.Consume` must atomically retrieve and delete a challenge to prevent replay attacks.
- Registration creates new accounts only; users log in separately after registering.

See [ifaces.go](ifaces.go) for detailed interface contracts and [_example/storage.go](_example/storage.go) for an in-memory reference implementation.

### 2. Configure and mount routes

Using your initialized storage implementations (see [_example/main.go](_example/main.go) for a runnable setup):

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/egregors/passkey"
)

func main() {
	pkey, err := passkey.New(
		passkey.Config{
			WebauthnConfig: &webauthn.Config{
				RPDisplayName: "My App",
				RPID:          "localhost",
				RPOrigins:     []string{"http://localhost:8080"},
			},
			UserStore:                userStore,
			LoginSessionStore:        loginSessionStore,
			RegistrationSessionStore: regSessionStore,
			UserSessionStore:         userSessionStore,
		},
		passkey.WithInsecureCookie(), // Use only for local HTTP development!
		passkey.WithUserSessionMaxAge(60 * time.Minute),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Mount ceremony routes under a trailing slash prefix (e.g. /api/)
	pkey.MountRoutes(mux, "/api/")

	// Mount logout separately at your application's logout endpoint
	mux.HandleFunc("/logout", pkey.Logout)

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### 3. Protect routes with middleware

Use `pkey.Auth` to protect authenticated endpoints. Pass a typed `AuthUserIDKey` to retrieve the authenticated user ID from context with `passkey.UserIDFromCtx`:

```go
const userKey passkey.AuthUserIDKey = "userID"

// Register inside main (before http.ListenAndServe):
mux.Handle("/private", pkey.Auth(userKey, nil, nil)(http.HandlerFunc(privateHandler)))

func privateHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := passkey.UserIDFromCtx(r.Context(), userKey)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Resolve the account and apply application authorization here...
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Authenticated user: %x", userID)
}
```

- When `onFail` is `nil`, unauthenticated requests return `401 Unauthorized`.
- You can provide a custom failure handler or use `passkey.RedirectUnauthorized(url.URL{Path: "/login"})`.
- When provided, `onSuccess` runs before the protected handler.
- The middleware validates the session; your application handlers remain responsible for verifying account status and application authorization.

### 4. Client-side integration

Connect any standard WebAuthn browser client:

1. **Registration**: POST `{"username":"alice"}` to `/api/passkey/registerBegin`, pass the returned options to a WebAuthn client (such as [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn)), and POST its serialized response to `/api/passkey/registerFinish`.
2. **Login**: POST `{"username":"alice"}` to `/api/passkey/loginBegin`, pass the returned options to the client, and POST the serialized assertion to `/api/passkey/loginFinish`.

See [_example/web](_example/web) for a complete vanilla frontend implementation.

## Endpoints

Ceremony routes use the `/api/` prefix below when mounted with `pkey.MountRoutes(mux, "/api/")`. `/logout` is mounted separately using `pkey.Logout` as shown above.

| Route | Method | Request Body | Description |
|---|---|---|---|
| `/api/passkey/registerBegin` | POST | `{"username":"alice"}` | Begin registration ceremony |
| `/api/passkey/registerFinish` | POST | WebAuthn registration response | Complete registration and save account |
| `/api/passkey/loginBegin` | POST | `{"username":"alice"}` | Begin login ceremony |
| `/api/passkey/loginFinish` | POST | WebAuthn assertion response | Verify login and set authenticated session |
| `/logout` | POST | Empty | Revoke session and clear cookie (returns 204) |

> [!NOTE]
> All ceremony endpoints and `Logout` require `POST` with an `Origin` header matching `RPOrigins`. Challenges are single-use and expire after at most five minutes; if verification fails, restart the ceremony at the begin endpoint.

## Options

Pass functional options to `passkey.New`:

| Option | Default | Description |
|---|---|---|
| `WithLogger(logger)` | Built-in logger | Provide a custom `passkey.Logger` |
| `WithInsecureCookie()` | Disabled | Use unprefixed, non-Secure cookies for local HTTP development |
| `WithSessionCookieNamePrefix(prefix)` | `"pk"` | Set base prefix for session cookies |
| `WithUserSessionMaxAge(duration)` | 60 minutes | Set authenticated-session lifetime and cookie max age |

Production cookies default to `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax` cookies served over HTTPS.

## Example Application

A complete runnable example is provided in [_example](_example):

```bash
# Run local HTTP example on http://localhost:8080
make run

# Run HTTPS example with self-signed certificate in Docker on https://localhost
make up
```

The example uses in-memory storage; restarting it removes accounts and sessions.

## Troubleshooting

### FAQ

**Q: I'm getting an error "named cookie not present" when I try to interact with passkey running on `localhost` from macOS Safari.**

A: For local HTTP development, use `WithInsecureCookie()` to disable Secure and reserved cookie prefixes. Production requires HTTPS with the default secure cookies.

**Q: Why do ceremony requests return 403 or an origin-related verification failure?**

A: Configure `RPOrigins` with the exact browser origin, including its scheme and nondefault port. POST requests must send that Origin header; WebAuthn verification also checks the origin in the signed client data.

**Q: I'm getting an error "WebAuthn is not supported in this browser" when I try to interact with passkey on `localhost` from iOS Safari.**

A: WebAuthn needs a browser-trusted secure context. Use HTTPS when testing from another device; `make up` starts the HTTPS example, whose local certificate must be trusted by the test device.

## Development

```bash
make test         # Run unit and integration tests
make install-lint # Install pinned golangci-lint
make lint         # Run linter
make gen          # Generate mocks
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

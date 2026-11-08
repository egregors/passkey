<div align="center">
    <h1>🔑 passkey</h1>

`passkey` is a Go library for implementing WebAuthn services

[![Build Status](https://github.com/egregors/passkey/workflows/build/badge.svg)](https://github.com/egregors/passkey/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/egregors/passkey)](https://goreportcard.com/report/github.com/egregors/passkey)
[![Coverage Status](https://coveralls.io/repos/github/egregors/passkey/badge.svg?branch=main)](https://coveralls.io/github/egregors/passkey?branch=main)
[![godoc](https://godoc.org/github.com/egregors/passkey?status.svg)](https://godoc.org/github.com/egregors/passkey)

</div>

---

## Table of Contents

<!-- TOC -->

* [Table of Contents](#table-of-contents)
* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
    * [Library Usage](#library-usage)
        * [Implement storage](#implement-storage)
        * [Create a new `Passkey` instance and mount the routes](#create-a-new-passkey-instance-and-mount-the-routes)
        * [Client-side](#client-side)
    * [Example Application](#example-application)
* [API](#api)
    * [Middleware](#middleware)
* [Development](#development)
    * [Common tasks](#common-tasks)
    * [Mocks](#mocks)
    * [Troubleshooting](#troubleshooting)
        * [FAQ](#faq)
* [Contributing](#contributing)
* [License](#license)

<!-- TOC -->

## Features

- **User Management**: Handle user information and credentials.
- **WebAuthn Integration**: Easily integrate with WebAuthn for authentication.
- **Session Management**: Manage user sessions securely.
- **Middleware Support**: Middleware for authenticated routes.

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

Use Go 1.25 or newer, as declared in [go.mod](go.mod).

Install the library using `go get`:

```bash
go get github.com/egregors/passkey
```

## Usage

### Library Usage

To add a passkey service to your application, you need to do a few simple steps:

#### Implement storage

Implement [`UserStore`, `User`, and `SessionStore[T]`](ifaces.go). Configure one
user store and three session stores:

| Configuration field | Record type | Purpose |
|---|---|---|
| `UserStore` | `User` | Accounts and registered credentials |
| `LoginSessionStore` | `webauthn.SessionData` | Pending login challenges |
| `RegistrationSessionStore` | `passkey.RegistrationSessionData` | Pending registration challenges and usernames |
| `UserSessionStore` | `passkey.UserSessionData` | Authenticated sessions |

`Create(passkey.NewUser)` must atomically save the account and its initial
credential, preserve the exact `UserID`, and enforce unique usernames and user IDs.
Return `passkey.ErrUserAlreadyExists` on conflicts. Unknown users must return
`passkey.ErrUserNotFound` from lookups; do not return a nil user with a nil error.
The library registers new accounts only; it does not attach credentials to an
existing account. Registration does not create an authenticated session: log in
separately afterward.

`User` implements `webauthn.User`. Storage reads and `Create` must return detached
snapshots, including credential byte slices. After verification, the library calls
`UpdateCredential` to atomically update an existing credential's authentication
state: signature counter, clone warning, and flags. Preserve registration data and
other credentials; ignore updates with older counters while retaining previously
observed clone warnings. Return `ErrUserNotFound` or `ErrCredentialNotFound` for
missing records.

#### Create a new `Passkey` instance and mount the routes

For a runnable integration, see:

- [`_example/main.go`](_example/main.go) configures all stores, mounts the ceremony
  routes under `/api/`, and protects `/private` with `Auth`.
- [`_example/storage.go`](_example/storage.go) and
  [`_example/models.go`](_example/models.go) implement in-memory user storage with detached snapshots and bounded session
  storage. Data is lost on restart.
- [`_example/main_test.go`](_example/main_test.go) exercises registration, signed
  login, private-page access, deleted users, and logout through the actual mux.
  `make test` and CI run these tests in the separate example module.

Pass the same user-store instance to `passkey.Config` and application handlers
that resolve the authenticated user ID. Mount routes with a trailing slash, for
example `pkey.MountRoutes(mux, "/api/")`. This exposes the following POST routes:

| Route | Request |
|---|---|
| `/api/passkey/registerBegin` | `{"username":"alice"}` |
| `/api/passkey/registerFinish` | WebAuthn registration response |
| `/api/passkey/loginBegin` | `{"username":"alice"}` |
| `/api/passkey/loginFinish` | WebAuthn assertion response |

Mount `pkey.Logout` separately at the application's logout path.

You can optionally provide a logger to the `New` function using the `WithLogger` option.

Full list of options:

| Name | Default | Description |
|---|---|---|
| WithLogger | `log.NewLogger()` | Provide a custom logger |
| WithInsecureCookie | Disabled | Use unprefixed, non-Secure cookies for local HTTP |
| WithSessionCookieNamePrefix | `pk` | Set the base prefix before the reserved `__Host-` prefix is applied |
| WithUserSessionMaxAge | 60 minutes | Set the authenticated-session lifetime and cookie max age |

#### Client-side

You need a client-side library that can be used to interact with the server-side library. In example app we use
[SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn) v13.3.0 library (check `_example/web` directory).
The example vendors the official ES5 UMD bundle, so it does not depend on a third-party CDN at runtime.

### Example Application

The library comes with an example application that demonstrates how to use it. To run the example application
just run the following command:

```bash
# go run local example app on http://localhost:8080 (no ssl)
make run 
```

or

```bash
# run example app in docker container on https://localhost (with self-signed certificate)
make up 
```

## API

After method/origin validation, all four passkey endpoints accept request bodies
up to 1 MiB. Larger bodies return HTTP 413 before storage or WebAuthn access, including when
`Content-Length` is unknown. Usernames must contain between 1 and 256 UTF-8 bytes;
invalid lengths return HTTP 400 before the username is logged or passed to storage.
These limits are fixed and apply to the decoded username and the entire raw request
body, respectively, including any trailing data.

Login and registration challenges are single-use. Once a finish request passes
the method/origin and body-size checks and supplies one ceremony cookie, it
atomically consumes that session before verification and clears the cookie on
success or failure. After a failed attempt, restart with the corresponding begin
endpoint. Session stores must implement `Consume` as an atomic retrieve-and-delete
operation, including across
application instances sharing storage. Requests rejected by the body limit do not
reach the handler and do not consume a challenge.

Login challenges expire on the server after at most five minutes, independently of
cookie expiration and storage TTL. A shorter expiration set by WebAuthn is preserved.
Expired sessions and legacy login sessions without an expiration are rejected and
consumed before user lookup or signature verification; the client must start a new
login ceremony. Registration sessions are also capped at five minutes, preserving
a shorter WebAuthn deadline. Session stores must enforce record expiration and reclaim
expired records to free space; do not extend deadlines when serializing records.

Authenticated sessions carry a purpose/version marker set after successful login.
`Auth` rejects sessions with a missing or incorrect marker, an empty user ID, or an
absent or elapsed expiration. Existing sessions without the marker require a new login.
Storage serialization must preserve all fields and must not fill in missing markers.
Use separate key namespaces for each of the three session stores and each
application/tenant scope. Tokens must be unique and cryptographically random with
at least 128 bits of entropy.

Session stores must have finite capacity and reclaim expired records before
refusing new sessions. Return `ErrSessionStoreFull` when full; handlers respond
with HTTP 503 and do not set a new session cookie. The example store retains at
most 1024 records per instance and removes expired entries on creation or lookup.
It needs no background cleanup goroutine.

Production cookies use `__Host-` names with `Secure`, `HttpOnly`, `SameSite=Lax`,
`Path=/`, and no `Domain`. Default names are `__Host-pkLsid`, `__Host-pkRsid`, and
`__Host-pkUsid` for login, registration, and authenticated sessions respectively.
`WithInsecureCookie` uses ordinary names for local HTTP development. Custom name
prefixes must form valid cookie names; invalid configuration fails in `New`.
Duplicate same-name session cookies are rejected, including during logout.

All ceremony endpoints and `Logout` require POST and exactly one `Origin` header
matching a configured `RPOrigins` value. Missing, `null`, or unlisted origins return
403; other methods return 405 with `Allow: POST`. Checks run before reading the
body or changing sessions. Non-browser clients must also send an allowed Origin;
this is CSRF protection and does not replace assertion/session verification.
Configure serialized origins (`scheme://host[:port]`, without a trailing slash).
Successful logout returns 204, including when its cookie is already absent.
Browser clients should POST logout and navigate after a successful response, as
shown in the example. Browsers with unprefixed production cookies require a new login.

Handler errors are JSON strings with fixed public messages. Invalid requests and
recognized verification failures return 400; missing users/credentials return 404,
registration conflicts 409, and session capacity exhaustion 503. Unexpected backend
or unclassified verification failures return 500 with `"internal server error"`.
Backend diagnostics and WebAuthn error details are never included in those responses.
Internal logging is retained; storage adapters must redact secrets from their errors.

Apply request admission/rate limiting in HTTP middleware before forwarding to
the mux populated by `MountRoutes`. This rejects requests before WebAuthn
generation or storage allocation, including requests without cookies. The policy
belongs to the application; storage capacity remains a separate hard limit.

| Method                                                                                            | Description                                                                                         |
|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `New(cfg Config, opts ...Option) (*Passkey, error)`                                               | Creates a new Passkey instance.                                                                     |
| `MountRoutes(mux *http.ServeMux, path string)`                                                    | Mounts the Passkey routes onto a given HTTP multiplexer.                                            |
| `Auth(userIDKey AuthUserIDKey, onSuccess, onFail http.HandlerFunc) func(next http.Handler) http.Handler` | Middleware to protect routes that require authentication.                                           |
| `UserIDFromCtx(ctx context.Context, pkUserKey AuthUserIDKey) ([]byte, bool)`                             | Returns the user ID from the request context. If the userID is not found, it returns nil and false. |

### Middleware

The library provides a middleware function that can be used to protect routes that require authentication.

```go
Auth(userIDKey AuthUserIDKey, onSuccess, onFail http.HandlerFunc) func (next http.Handler) http.Handler
```

It takes key for context and two callback functions that are called when the user is authenticated or not.
You can use the context key to retrieve the authenticated userID from the request context
with `passkey.UserIDFromCtx`.

When `onFail` is nil, rejected authentication returns HTTP 401. A supplied failure
callback controls the response instead. Rejection never invokes `onSuccess` or
the protected handler; a nil `onSuccess` simply skips that callback.

`passkey` contains a helper function:

| Helper                       | Description                                                             |
|------------------------------|-------------------------------------------------------------------------|
| Unauthorized                 | Returns a 401 Unauthorized response when the user is not authenticated. |
| RedirectUnauthorized(target) | Redirects the user to a local URL when they are not authenticated.      |
| UserIDFromCtx                | Returns the authenticated user ID from context.                         |

Use a typed key such as `const userKey passkey.AuthUserIDKey = "pkUser"` for both
`pkey.Auth` and `passkey.UserIDFromCtx`. The example's
[`exampleMux` and `privateHandler`](_example/main.go) show this wiring.

On success, `Auth` sets the user ID in the request context, runs `onSuccess` if
provided, and then always calls the protected handler. A success callback cannot
stop the request. The middleware validates the session, not the current account
record: application handlers must handle deleted users, and the application must
revoke sessions when its account lifecycle or authorization policy requires it.
`RedirectUnauthorized` returns a 303 redirect for local targets and falls back to
401 for rejected targets.

## Development

### Common tasks

The golangci-lint version is pinned in `.golangci-lint-version` and shared by local `make lint` and GitHub Actions.
Run `make install-lint` to install the required version, then use `make` for common development tasks:

```bash
➜  passkey git:(main) make help
Usage: make [task]

task                 help
------               ----
                     
lint                 Lint the files
install-lint         Install the pinned golangci-lint version
test                 Run unittests
run                  Run example project
up                   Run example project with local SSL (self-signed certificate)
gen                  Generate mocks
update-go-deps       Updating Go dependencies
                     
help                 Show help message

```

### Mocks

Use [mockery](https://github.com/vektra/mockery) to generate mocks for interfaces.

### Troubleshooting

#### FAQ

**Q: I'm getting an error "named cookie not present" when I try to interact with passkey running on `localhost` from
macOS Safari.**

A: For local HTTP development, use `WithInsecureCookie` to disable Secure and
reserved cookie prefixes. Production requires HTTPS with the default secure cookies.

**Q: Why do ceremony requests return 403 or an origin-related verification failure?**

A: Configure `RPOrigins` with the exact browser origin, including its scheme and
nondefault port. POST requests must send that Origin header; WebAuthn verification
also checks the origin in the signed client data.

**Q: I'm getting an error "WebAuthn in not supported in this browser" when I try to interact with passkey on `localhost`
from iOS Safari.**

A: WebAuthn needs a browser-trusted secure context. Use HTTPS when testing from
another device; `make up` starts the HTTPS example, whose local certificate must be
trusted by the test device.

## Contributing

Bug reports, bug fixes and new features are always welcome. Please open issues and submit pull requests for any new
code.

## License

This project is licensed under the MIT License - see
the [LICENSE](https://github.com/egregors/passkey/blob/main/LICENSE) file for details.

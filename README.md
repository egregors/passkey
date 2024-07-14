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

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
    - [Library Usage](#library-usage)
    - [Example Application](#example-application)
- [API](#api)
- [License](#license)

## Features

- **User Management**: Handle user information and credentials.
- **WebAuthn Integration**: Easily integrate with WebAuthn for authentication.
- **Session Management**: Manage user sessions securely.
- **Middleware Support**: Implement middleware for authenticated routes.

> [!WARNING]  
> Stable version is not released yet. The API and the lib are under development.

> [!NOTE]
> In general, this library is built on top of two open-source solutions:
> * Golang WebAuthn Library – https://github.com/go-webauthn/webauthn
> * JS/TS SimpleWebAuthn client – https://github.com/MasterKale/SimpleWebAuthn

Used in project:
![Static Badge](https://img.shields.io/badge/Go_WebAuthn-v0.10.2-green)
![Static Badge](https://img.shields.io/badge/TS%5CJS%20SimpleWebAuthn-v10.0.0-green)

Actual versions: 
![GitHub Release](https://img.shields.io/github/v/release/go-webauthn/webauthn?label=Go%20WebAuthn)
![GitHub Release](https://img.shields.io/github/v/release/MasterKale/SimpleWebAuthn?label=TS%5CJS%20SimpleWebAuthn)

## Installation

To get started, you need to have Go installed on your machine. If you don't have it installed,
you can download it from [here](https://golang.org/dl/).

Install the library using `go get`:

```bash
go get github.com/egregors/passkey
```

## Usage

### Library Usage

To add a passkey service to your application, you need to do two things:

#### Implement the `UserStore` and `SessionStore` interfaces

```go
type User interface {
  webauthn.User
  PutCredential(webauthn.Credential)
}

type UserStore interface {
  GetOrCreateUser(userName string) User
  SaveUser(User)
}

type SessionStore interface {
  GenSessionID() (string, error)
  GetSession(token string) (*webauthn.SessionData, bool)
  SaveSession(token string, data *webauthn.SessionData)
  DeleteSession(token string)
}

```

#### Create a new `Passkey` instance and mount the routes

```go
package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/egregors/passkey"
	"github.com/go-webauthn/webauthn/webauthn"
)

func main() {
	proto := "http"
	host := "localhost"
	port := ":8080"
	origin := fmt.Sprintf("%s://%s%s", proto, host, port)

	storage := NewStorage()

	pkey, err := passkey.New(
		passkey.Config{
			WebauthnConfig: &webauthn.Config{
				RPDisplayName: "Passkey Example", // Display Name for your site
				RPID:          host,              // Generally the FQDN for your site
				RPOrigins:     []string{origin},  // The origin URLs allowed for WebAuthn
			},
			UserStore:     storage,
			SessionStore:  storage,
			SessionMaxAge: 60 * time.Minute,
		},
		passkey.WithLogger(NewLogger()),
	)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	pkey.MountRoutes(mux, "/api/")
	pkey.MountStaticRoutes(mux, "/static/")

	mux.Handle("/", http.FileServer(http.Dir("./_example/web")))

	privateMux := http.NewServeMux()
	privateMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// render html from web/private.html
		http.ServeFile(w, r, "./_example/web/private.html")
	})
	withAuth := passkey.Auth(storage)
	mux.Handle("/private", withAuth(privateMux))

	if err := http.ListenAndServe(port, mux); err != nil {
		panic(err)
	}
}
```

You can optionally provide a logger to the `New` function using the `WithLogger` option.

### Example Application

The library comes with an example application that demonstrates how to use the library. To run the example application,
navigate to the `_example` directory and run the following command:

```bash
make run
```

This will start the example application on http://localhost:8080.

## API

| Method                                               | Description                                              |
|------------------------------------------------------|----------------------------------------------------------|
| `New(cfg Config, opts ...Option) (*Passkey, error)`  | Creates a new Passkey instance.                          |
| `MountRoutes(mux *http.ServeMux, path string)`       | Mounts the Passkey routes onto a given HTTP multiplexer. |
| `MountStaticRoutes(mux *http.ServeMux, path string)` | Mounts the static routes onto a given HTTP multiplexer.  |

### Middleware

The library provides a middleware function that can be used to protect routes that require authentication.

```go
func Auth(sessionStore SessionStore, onSuccess, onFail http.HandlerFunc) func (next http.Handler) http.Handler {
```

It takes two callback functions that are called when the user is authenticated or not.

`passkey` contains a helper function:

| Helper                       | Description                                                             |
|------------------------------|-------------------------------------------------------------------------|
| Unauthorized                 | Returns a 401 Unauthorized response when the user is not authenticated. |
| RedirectUnauthorized(target) | Redirects the user to a given URL when they are not authenticated.      |

You can use it to protect routes that require authentication:

```go
package main

import (
  "net/url"

  "github.com/egregors/passkey"
)

func main() {
  // ...
  withAuth := passkey.Auth(
    storage,
    nil,
    passkey.RedirectUnauthorized(url.URL{Path: "/"}),
  )

  mux.Handle("/private", withAuth(privateMux))
}

```

## Development

### Common tasks

To common dev task just use `make`:

```bash
➜  passkey git:(main) make help
Usage: make [task]

task                 help
------               ----

lint                 Lint the files
test                 Run unittests
run                  Run example project
gen                  Generate mocks
update-go-deps       Updating Go dependencies

help                 Show help message
```

### Mocks

Use [mockery](https://github.com/vektra/mockery) to generate mocks for interfaces.

```

## License

This project is licensed under the MIT License - see
the [LICENSE](https://github.com/egregors/passkey/blob/main/LICENSE) file for details.

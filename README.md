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
      * [Implement the `UserStore` and `SessionStore` interfaces](#implement-the-userstore-and-sessionstore-interfaces)
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
- **Middleware Support**: Implement middleware for authenticated routes.

> [!WARNING]  
> Stable version is not released yet. The API and the lib are under development.

> [!NOTE]
> In general, this library is built on top of two open-source solutions:
> * Golang WebAuthn Library – https://github.com/go-webauthn/webauthn
> * JS/TS SimpleWebAuthn client – https://github.com/MasterKale/SimpleWebAuthn

Used in project:
![Static Badge](https://img.shields.io/badge/Go_WebAuthn-v0.11.1-green)
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
package passkey

import "github.com/go-webauthn/webauthn/webauthn"

type User interface {
	webauthn.User
	PutCredential(webauthn.Credential)
}

type UserStore interface {
	GetOrCreateUser(UserID string) User
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
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/egregors/passkey"
	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed web/*
var webFiles embed.FS

const userKey = "pkUser"

func main() {
	proto := getEnv("PROTO", "http")             // "http" | "https"
	sub := getEnv("SUB", "")                     // "" | "login."
	host := getEnv("HOST", "localhost")          // "localhost" | "example.com"
	originPort := getEnv("ORIGIN_PORT", ":8080") // ":8080" | "" if you use reverse proxy it should be the most "external" port
	serverPort := getEnv("SERVER_PORT", ":8080") // ":8080"

	origin := fmt.Sprintf("%s://%s%s%s", proto, sub, host, originPort)

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
			SessionMaxAge: 24 * time.Hour,
		},
		passkey.WithLogger(NewLogger()),
		passkey.WithCookieMaxAge(60*time.Minute),
		passkey.WithInsecureCookie(), // In order to support Safari on localhost. Do not use in production.
	)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	// mount the passkey routes
	pkey.MountRoutes(mux, "/api/")

	// public routes
	web, _ := fs.Sub(webFiles, "web")
	mux.Handle("/", http.FileServer(http.FS(web)))
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		pkey.Logout(w, r)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// private routes
	privateMux := http.NewServeMux()
	privateMux.HandleFunc("/", privateHandler())

	// wrap the privateMux with the Auth middleware
	withAuth := pkey.Auth(
		userKey,
		nil,
		passkey.RedirectUnauthorized(url.URL{Path: "/"}),
	)
	mux.Handle("/private", withAuth(privateMux))

	// start the server
	fmt.Printf("Listening on %s\n", origin)
	if err := http.ListenAndServe(serverPort, mux); err != nil {
		panic(err)
	}
}

```

You can optionally provide a logger to the `New` function using the `WithLogger` option.

Full list of options:

| Name                  | Default                                | Description                            |
|-----------------------|----------------------------------------|----------------------------------------|
| WithLogger            | NullLogger                             | Provide custom logger                  |
| WithInsecureCookie    | Disabled (cookie is secure by default) | Sets Cookie.Secure to false            |
| WithSessionCookieName | `sid`                                  | Sets the name of the session cookie    |
| WithCookieMaxAge      | 60 minutes                             | Sets the max age of the session cookie |

#### Client-side

You need a client-side library that can be used to interact with the server-side library. In example app we use
[SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn) library (check `_example/web` directory).

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

| Method                                                                                            | Description                                               |
|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `New(cfg Config, opts ...Option) (*Passkey, error)`                                               | Creates a new Passkey instance.                           |
| `MountRoutes(mux *http.ServeMux, path string)`                                                    | Mounts the Passkey routes onto a given HTTP multiplexer.  |
| `Auth(userIDKey string, onSuccess, onFail http.HandlerFunc) func(next http.Handler) http.Handler` | Middleware to protect routes that require authentication. |

### Middleware

The library provides a middleware function that can be used to protect routes that require authentication.

```go
Auth(userIDKey string, onSuccess, onFail http.HandlerFunc) func (next http.Handler) http.Handler
```

It takes key for context and two callback functions that are called when the user is authenticated or not.
You can use the context key to retrieve the authenticated userID from the request context
with `passkey.UserFromContext`.

`passkey` contains a helper function:

| Helper                       | Description                                                             |
|------------------------------|-------------------------------------------------------------------------|
| Unauthorized                 | Returns a 401 Unauthorized response when the user is not authenticated. |
| RedirectUnauthorized(target) | Redirects the user to a given URL when they are not authenticated.      |
| UserFromContext              | Get userID from context                                                 |

You can use it to protect routes that require authentication:

```go
package main

import (
	"net/url"

	"github.com/egregors/passkey"
)

func main() {
	pkey, err := passkey.New(...)
	check(err)

	withAuth := pkey.Auth(
		"pkUser",
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
up                   Run example project with local SSL (self-signed certificate)
gen                  Generate mocks
update-go-deps       Updating Go dependencies
                     
help                 Show help message

```

### Mocks

Use [mockery](https://github.com/vektra/mockery) to generate mocks for interfaces.A

### Troubleshooting

#### FAQ

**Q: I'm getting an error "named cookie not present" when I try to interact with passkey running on `localhost` from
macOS Safari.**

A: This is a known issue with Safari and localhost. You can work around it by using the `WithInsecureCookie` option when
creating a new `Passkey` instance. This will set the `Secure` flag on the session cookie to `false`.

**Q: I'm getting an error "Error validating origin" when I try to interact with passkey.**

A: This error occurs when the origin URL is not included in the `RPOrigins` list. Make sure that the origin URL is
included in the `RPOrigins` list when creating a new `Passkey` instance.

**Q: I'm getting an error "WebAuthn in not supported in this browser" when I try to interact with passkey on `localhost`
from iOS Safari.**

A: Mobile Safari no not store insecure cookies. To play around with the example app on iOS Safari, you should run in
with self-signed certificate. Use `make up` to run the example app in docker container with self-signed certificate.

## Contributing

Bug reports, bug fixes and new features are always welcome. Please open issues and submit pull requests for any new
code.

## License

This project is licensed under the MIT License - see
the [LICENSE](https://github.com/egregors/passkey/blob/main/LICENSE) file for details.

# Passkey

Passkey is a simple and secure authentication library for Go that uses WebAuthn for user registration and login.

## Features

- User registration and login using WebAuthn.
- Simple and clean user interface.
- Secure authentication using biometrics or security keys.

## Prerequisites

- Go
- A modern web browser that supports WebAuthn.

## Installation

Clone the repository:

```bash
git clone https://github.com/egregors/passkey.git
```

Navigate to the project directory:

```bash
cd passkey
```

Install the dependencies:

```bash
go mod download
```

## Usage

Sure, here's an example of how you can use the `passkey` library in a Go project:

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/egregors/passkey"
	"github.com/go-webauthn/webauthn/webauthn"
)

func main() {
	proto := "http"
	host := "localhost"
	port := ":8080"
	origin := fmt.Sprintf("%s://%s%s", proto, host, port)

	// Create a new storage for users and sessions
	storage := NewStorage()

	// Initialize the passkey library
	pkey, err := passkey.New(
		passkey.Config{
			WebauthnConfig: &webauthn.Config{
				RPDisplayName: "Passkey Example", // Display Name for your site
				RPID:          host,              // Generally the FQDN for your site
				RPOrigins:     []string{origin},  // The origin URLs allowed for WebAuthn
			},
			UserStore:     storage,
			SessionStore:  storage,
			SessionMaxAge: 3600,
		},
		passkey.WithLogger(NewLogger()),
	)
	if err != nil {
		panic(err)
	}

	// Create a new HTTP ServeMux
	mux := http.NewServeMux()

	// Mount the passkey routes
	pkey.MountRoutes(mux, "/api/")
	pkey.MountStaticRoutes(mux, "/static/")

	// Serve static files
	mux.Handle("/", http.FileServer(http.Dir("./_example/web")))

	// Create a new HTTP ServeMux for private routes
	privateMux := http.NewServeMux()
	privateMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// render html from web/private.html
		http.ServeFile(w, r, "./_example/web/private.html")
	})

	// Add authentication to the private routes
	withAuth := passkey.Auth(storage)
	mux.Handle("/private", withAuth(privateMux))

	// Start the server
	if err := http.ListenAndServe(port, mux); err != nil {
		panic(err)
	}
}
```

In this example, we're creating a new instance of `passkey` with a configuration that includes a `WebauthnConfig`,
a `UserStore`, a `SessionStore`, and a `SessionMaxAge`. We're also adding a logger to the `passkey` instance.

We then create a new HTTP server and mount the `passkey` routes to it. We also serve static files from a directory.

For private routes, we create a new HTTP server, add a route to it, and then add authentication to these routes using
the `Auth` function from `passkey`.

Finally, we start the server.

Please replace `NewStorage` and `NewLogger` with your own implementations.

## API Endpoints

| Endpoint                  | Description                        | Required Parameters       |
|---------------------------|------------------------------------|---------------------------|
| `/passkey/registerBegin`  | Starts the registration process.   | Username                  |
| `/passkey/registerFinish` | Finishes the registration process. | Session ID, User Response |
| `/passkey/loginBegin`     | Starts the login process.          | Username                  |
| `/passkey/loginFinish`    | Finishes the login process.        | Session ID, User Response |

## Middleware

- `Auth`: Implements a middleware handler for adding passkey http auth to a route.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
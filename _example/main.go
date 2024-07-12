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

	fmt.Printf("Listening on %s\n", port)
	if err := http.ListenAndServe(port, mux); err != nil {
		panic(err)
	}
}

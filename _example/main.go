package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/egregors/passkey"
	"github.com/go-webauthn/webauthn/webauthn"
)

const userKey = "pkUser"

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
	pkey.MountStaticRoutes(mux, "/static/")

	// public routes
	mux.Handle("/", http.FileServer(http.Dir("./_example/web")))
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
	if err := http.ListenAndServe(port, mux); err != nil {
		panic(err)
	}
}

func privateHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get the userID from the request context
		userID, ok := passkey.UserFromContext(r.Context(), userKey)
		if !ok {
			http.Error(w, "No user found", http.StatusUnauthorized)

			return
		}

		pageData := struct {
			UserID string
		}{
			UserID: userID,
		}

		tmpl, err := template.ParseFiles("./_example/web/private.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		if err := tmpl.Execute(w, pageData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
	}
}

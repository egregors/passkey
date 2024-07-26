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
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		pkey.Logout(w, r)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	privateMux := http.NewServeMux()
	privateMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
	})

	withAuth := passkey.Auth(
		storage,
		userKey,
		nil,
		passkey.RedirectUnauthorized(url.URL{Path: "/"}),
	)

	mux.Handle("/private", withAuth(privateMux))

	fmt.Printf("Listening on %s\n", origin)
	if err := http.ListenAndServe(port, mux); err != nil {
		panic(err)
	}
}

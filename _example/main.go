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

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/egregors/passkey"
	"github.com/egregors/passkey/log"
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

	l := log.NewLogger()

	pkey, err := passkey.New(
		passkey.Config{
			WebauthnConfig: &webauthn.Config{
				RPDisplayName: "Passkey Example", // Display Name for your site
				RPID:          host,              // Generally the FQDN for your site
				RPOrigins:     []string{origin},  // The origin URLs allowed for WebAuthn
			},
			UserStore:         NewUserStore(),
			AuthSessionStore:  NewSessionStore[webauthn.SessionData](),
			UserSessionStore:  NewSessionStore[passkey.UserSessionData](),
			UserSessionMaxAge: 24 * time.Hour,
		},
		passkey.WithLogger(l),
		passkey.WithUserSessionMaxAge(60*time.Minute),
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
	l.Infof("Listening on %s\n", origin)
	if err := http.ListenAndServe(serverPort, mux); err != nil {
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

		tmpl, err := template.ParseFS(webFiles, "web/private.html")
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

func getEnv(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return defaultValue
}

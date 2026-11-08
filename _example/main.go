package main

import (
	"bytes"
	"embed"
	"errors"
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

const userKey passkey.AuthUserIDKey = "pkUser"

func main() {
	proto := getEnv("PROTO", "http")             // "http" | "https"
	sub := getEnv("SUB", "")                     // "" | "login."
	host := getEnv("HOST", "localhost")          // "localhost" | "example.com"
	originPort := getEnv("ORIGIN_PORT", ":8080") // ":8080" | "" if you use reverse proxy it should be the most "external" port
	serverPort := getEnv("SERVER_PORT", ":8080") // ":8080"

	origin := fmt.Sprintf("%s://%s%s%s", proto, sub, host, originPort)

	l := log.NewLogger()
	l.Enable(log.DBG)

	opts := []passkey.Option{
		passkey.WithLogger(l),
		passkey.WithUserSessionMaxAge(60 * time.Minute),
		passkey.WithSessionCookieNamePrefix("passkeyDemo"),
	}
	if proto == "http" {
		opts = append(opts, passkey.WithInsecureCookie())
	}
	users := NewUserStore()
	pkey, err := passkey.New(
		passkey.Config{
			WebauthnConfig: &webauthn.Config{
				RPDisplayName: "Passkey Example", // Display Name for your site
				RPID:          host,              // Generally the FQDN for your site
				RPOrigins:     []string{origin},  // The origin URLs allowed for WebAuthn
			},
			UserStore:                users,
			LoginSessionStore:        NewSessionStore[webauthn.SessionData](),
			RegistrationSessionStore: NewSessionStore[passkey.RegistrationSessionData](),
			UserSessionStore:         NewSessionStore[passkey.UserSessionData](),
		},
		opts...,
	)
	if err != nil {
		panic(err)
	}

	l.Infof("Listening on %s\n", origin)
	if err := http.ListenAndServe(serverPort, exampleMux(pkey, users)); err != nil { //nolint:gosec // example server
		panic(err)
	}
}

func exampleMux(pkey *passkey.Passkey, users passkey.UserStore) *http.ServeMux {
	mux := http.NewServeMux()
	pkey.MountRoutes(mux, "/api/")
	web, _ := fs.Sub(webFiles, "web")
	mux.Handle("/", http.FileServer(http.FS(web)))
	mux.HandleFunc("/logout", pkey.Logout)
	mux.Handle("/private", pkey.Auth(userKey, nil, passkey.RedirectUnauthorized(url.URL{Path: "/"}))(privateHandler(users)))
	return mux
}

func privateHandler(users passkey.UserStore) http.HandlerFunc {
	tmpl := template.Must(template.ParseFS(webFiles, "web/private.html"))
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := passkey.UserIDFromCtx(r.Context(), userKey)
		if !ok {
			http.Error(w, "No user found", http.StatusUnauthorized)

			return
		}

		user, err := users.Get(userID)
		if errors.Is(err, passkey.ErrUserNotFound) {
			http.Error(w, "No user found", http.StatusUnauthorized)
			return
		}
		if err != nil || user == nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		pageData := struct {
			UserID string
		}{
			UserID: user.WebAuthnName(),
		}

		var page bytes.Buffer
		if err := tmpl.Execute(&page, pageData); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(page.Bytes())
	}
}

func getEnv(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return defaultValue
}

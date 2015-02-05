package snsauth

import (
	"testing"

	"github.com/go-martini/martini"
	"github.com/martini-contrib/sessions"
	"golang.org/x/oauth2"
)

// TODO(jbd): Remove after Go 1.4.
// Related to https://codereview.appspot.com/107320046
func TestA(t *testing.T) {}

func ExampleLogin() {
	m := martini.Classic()
	m.Use(sessions.Sessions("my_session", sessions.NewCookieStore([]byte("secret123"))))
	m.Use(Google(
		&oauth2.Config{
			ClientID:     "client_id",
			ClientSecret: "client_secret",
			Scopes:       []string{"https://www.googleapis.com/auth/drive"},
			RedirectURL:  "redirect_url",
		},
	))

	// Tokens are injected to the handlers
	m.Get("/", func(tokens Tokens) string {
		if tokens.Expired() {
			return "not logged in, or the access token is expired"
		}
		return "logged in"
	})

	// Routes that require a logged in user
	// can be protected with oauth2.LoginRequired handler.
	// If the user is not authenticated, they will be
	// redirected to the login path.
	m.Get("/restrict", LoginRequired, func(tokens Tokens) string {
		return tokens.Access()
	})

	m.Run()
}

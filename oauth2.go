// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package oauth2 contains Martini handlers to provide
// user login via an OAuth 2.0 backend.
package snsauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-martini/martini"
	"github.com/martini-contrib/sessions"
	"github.com/philsong/oauth2"
)

const (
	codeRedirect = 302
	keyToken     = "oauth2_token"
	keyNextPage  = "next"
)

var (
	// PathLogin is the path to handle OAuth 2.0 logins.
	PathLogin = "/oauth2login"
	// PathLogout is the path to handle OAuth 2.0 logouts.
	PathLogout = "/oauth2logout"
	// PathCallback is the path to handle callback from OAuth 2.0 backend
	// to exchange credentials.
	//PathCallback = "/oauth2callback"
	PathCallback = "/callback"
	// PathError is the path to handle error cases.
	PathError = "/oauth2error"
)

// Options represents OAuth 2.0 credentials and
// further configuration to be used during access token retrieval.
type Options oauth2.Config

// Tokens represents a container that contains user's OAuth 2.0 access and refresh tokens.
type Tokens interface {
	Access() string
	Refresh() string
	Expired() bool
	ExpiryTime() time.Time
	ProviderName() string
}

type token struct {
	oauth2.Token
	providerName string
}

// Access returns the access token.
func (t *token) Access() string {
	if t == nil {
		fmt.Println("token.Access.t=nil")
		return ""
	}
	fmt.Println("token.AccessToken:", t.AccessToken)
	return t.AccessToken
}

// Refresh returns the refresh token.
func (t *token) Refresh() string {
	if t == nil {
		fmt.Println("token.Refresh.t=nil")
		return ""
	}

	fmt.Println("token.Refresh:", t.RefreshToken)
	return t.RefreshToken
}

// Expired returns whether the access token is expired or not.
func (t *token) Expired() bool {
	if t == nil {
		fmt.Println("token.Expired.t=nil")
		return true
	}
	fmt.Println("token.Expired:", !t.Token.Valid())
	return !t.Token.Valid()
}

// ExpiryTime returns the expiry time of the user's access token.
func (t *token) ExpiryTime() time.Time {
	if t == nil {
		fmt.Println("token.ExpiryTime.t=nil")
	}

	fmt.Println("token.Expiry:", t.Expiry)
	return t.Expiry
}

func (t *token) ProviderName() string {
	return t.providerName
}

// String returns the string representation of the token.
func (t *token) String() string {
	if t == nil {
		fmt.Println("token.String.t=nil")
		return ""
	}

	return fmt.Sprintf("token.Token: %v", t.Token)
}

// Google returns a new Google OAuth 2.0 backend endpoint.
func Google(conf *oauth2.Config) martini.Handler {
	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://accounts.google.com/o/oauth2/auth",
		TokenURL: "https://accounts.google.com/o/oauth2/token",
	}

	return NewOAuth2Provider(conf, "Google")
}

// Github returns a new Github OAuth 2.0 backend endpoint.
func Github(conf *oauth2.Config) martini.Handler {
	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	}

	return NewOAuth2Provider(conf, "Github")
}

// Facebook returns a new Facebook OAuth 2.0 backend endpoint.
func Facebook(conf *oauth2.Config) martini.Handler {
	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://www.facebook.com/dialog/oauth",
		TokenURL: "https://graph.facebook.com/oauth/access_token",
	}

	return NewOAuth2Provider(conf, "Facebook")
}

// LinkedIn returns a new LinkedIn OAuth 2.0 backend endpoint.
func LinkedIn(conf *oauth2.Config) martini.Handler {
	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://www.linkedin.com/uas/oauth2/authorization",
		TokenURL: "https://www.linkedin.com/uas/oauth2/accessToken",
	}

	return NewOAuth2Provider(conf, "LinkedIn")
}

func Dropbox(conf *oauth2.Config) martini.Handler {
	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://www.dropbox.com/1/oauth2/authorize",
		TokenURL: "https://api.dropbox.com/1/oauth2/token",
	}

	return NewOAuth2Provider(conf, "Dropbox")
}

func Tencent(conf *oauth2.Config) martini.Handler {
	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://graph.qq.com/oauth2.0/authorize",
		TokenURL: "https://graph.qq.com/oauth2.0/token",
	}

	return NewOAuth2Provider(conf, "Tencent")
}

func Weibo(conf *oauth2.Config) martini.Handler {
	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://api.weibo.com/oauth2/authorize",
		TokenURL: "https://api.weibo.com/oauth2/access_token",
	}

	return NewOAuth2Provider(conf, "Weibo")
}

func Weixin(conf *oauth2.Config) martini.Handler {
	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://open.weixin.qq.com/connect/qrconnect",
		TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token",
	}

	return NewOAuth2Provider(conf, "Weixin")
}

// NewOAuth2Provider returns a generic OAuth 2.0 backend endpoint.
func NewOAuth2Provider(conf *oauth2.Config, providerName string) martini.Handler {

	return func(s sessions.Session, c martini.Context, w http.ResponseWriter, r *http.Request) {
		fmt.Println("NewOAuth2Provider.r.URL.Path", r.Method, r.URL.Path, providerName)
		if r.Method == "GET" {
			switch r.URL.Path {
			case PathLogin:
				login(conf, s, w, r)
			case PathLogout:
				logout(s, w, r)
			case PathCallback:
				handleOAuth2Callback(conf, s, w, r)
			}
		}

		fmt.Println("NewOAuth2Provider.unmarshallToken", providerName)
		tk := unmarshallToken(s, providerName)
		if tk != nil {
			fmt.Println("NewOAuth2Provider. tk != nil")
			// check if the access token is expired
			if tk.Expired() && tk.Refresh() == "" {

				s.Delete(keyToken)
				tk = nil
			}
		} else {
			fmt.Println("NewOAuth2Provider. tk == nil")
		}

		// Inject tokens.
		c.MapTo(tk, (*Tokens)(nil))
	}
}

// Handler that redirects user to the login page
// if user is not logged in.
// Sample usage:
// m.Get("/login-required", oauth2.LoginRequired, func() ... {})
var LoginRequired = func() martini.Handler {
	return func(s sessions.Session, c martini.Context, w http.ResponseWriter, r *http.Request) {
		fmt.Println("LoginRequired.unmarshallToken")
		token := unmarshallToken(s, "")
		if token == nil {
			fmt.Println("LoginRequired.token is nil")
		} else {
			fmt.Println("LoginRequired.token", token)
		}

		if token == nil || token.Expired() {
			next := url.QueryEscape(r.URL.RequestURI())
			fmt.Println("LoginRequired.next", r.URL.RequestURI(), next)
			http.Redirect(w, r, PathLogin+"?next="+next, codeRedirect)
		}
	}
}()

func login(f *oauth2.Config, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get(keyNextPage))
	fmt.Println("login.next", next)
	if s.Get(keyToken) == nil {
		// User is not logged in.
		fmt.Println("login.s.Get(keyToken) == nil")
		if next == "" {
			next = "/"
		}
		http.Redirect(w, r, f.AuthCodeURL(next, oauth2.AccessTypeOffline), codeRedirect)
		//http.Redirect(w, r, f.AuthCodeURL(next), codeRedirect) //just for dropbox
		return
	}
	// No need to login, redirect to the next page.
	http.Redirect(w, r, next, codeRedirect)
}

func logout(s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get(keyNextPage))
	s.Delete(keyToken)
	fmt.Println("logout.next", next)
	http.Redirect(w, r, next, codeRedirect)
}

func handleOAuth2Callback(f *oauth2.Config, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get("state"))
	code := r.URL.Query().Get("code")
	fmt.Println("handleOAuth2Callback.next", next, " code", code)
	t, err := f.Exchange(oauth2.NoContext, code)
	if err != nil {
		// Pass the error message, or allow dev to provide its own
		// error handler.
		fmt.Println("handleOAuth2Callback.err", err)
		http.Redirect(w, r, PathError, codeRedirect)
		return
	}
	// Store the credentials in the session.
	fmt.Println("handleOAuth2Callback.t", t)
	val, _ := json.Marshal(t)
	s.Set(keyToken, val)

	http.Redirect(w, r, next, codeRedirect)
}

func unmarshallToken(s sessions.Session, providerName string) (t *token) {
	if s.Get(keyToken) == nil {
		fmt.Println("unmarshallToken.nil")
		return
	}
	data := s.Get(keyToken).([]byte)
	var tk oauth2.Token
	fmt.Println("unmarshallToken.data", data)
	json.Unmarshal(data, &tk)
	fmt.Println("unmarshallToken.tk", tk)
	return &token{tk, providerName}
}

func extractPath(next string) string {
	n, err := url.Parse(next)
	if err != nil {
		return "/"
	}
	return n.Path
}

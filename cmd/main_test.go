package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/seiferma/nginxmailauthdelegator/internal"
	"github.com/seiferma/nginxmailauthdelegator/internal/asserts"
)

func TestInvalidRequestMissingAttempts(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(1, "plain", "smtp", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})
	r.Header.Del("Auth-Login-Attempt")

	http_handler(w, r, &auth_handler)

	asserts.AssertNotEquals(t, "OK", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "", w.Header().Get("Auth-Wait"))
}

func TestInvalidRequestMissingProtocol(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(1, "plain", "smtp", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})
	r.Header.Del("Auth-Protocol")

	http_handler(w, r, &auth_handler)

	asserts.AssertNotEquals(t, "OK", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "", w.Header().Get("Auth-Wait"))
}

func TestInvalidRequestUnsupportedMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(1, "cram-md5", "smtp", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})

	http_handler(w, r, &auth_handler)

	asserts.AssertNotEquals(t, "OK", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "2", w.Header().Get("Auth-Wait"))
}

func TestInvalidRequestUsingMutualTls(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(1, "plain", "smtp", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})
	r.Header.Add("Auth-SSL", "on")

	http_handler(w, r, &auth_handler)

	asserts.AssertNotEquals(t, "OK", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "2", w.Header().Get("Auth-Wait"))
}

func TestInvalidSmtpCredentialsAuthRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(1, "plain", "smtp", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})

	http_handler(w, r, &auth_handler)

	asserts.AssertEquals(t, "Invalid login or password", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "535 5.7.8", w.Header().Get("Auth-Error-Code"))
	asserts.AssertEquals(t, "2", w.Header().Get("Auth-Wait"))
}

func TestInvalidImapCredentialsAuthRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(1, "plain", "imap", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})

	http_handler(w, r, &auth_handler)

	asserts.AssertEquals(t, "Invalid login or password", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "", w.Header().Get("Auth-Error-Code"))
	asserts.AssertEquals(t, "2", w.Header().Get("Auth-Wait"))
}

func TestInvalidCredentialsTooManyTriesAuthRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(3, "plain", "imap", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})

	http_handler(w, r, &auth_handler)

	asserts.AssertNotEquals(t, "OK", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "", w.Header().Get("Auth-Wait"))
}

func TestValidImapCredentialsAuthRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(1, "plain", "imap", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return true, true
	})

	http_handler(w, r, &auth_handler)

	asserts.AssertEquals(t, "OK", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "imap.example.org", w.Header().Get("Auth-Server"))
	asserts.AssertEquals(t, "993", w.Header().Get("Auth-Port"))
	asserts.AssertEquals(t, "", w.Header().Get("Auth-User"))
	asserts.AssertEquals(t, "", w.Header().Get("Auth-Pass"))
}

func TestValidImtpCredentialsAuthRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := createRequest(1, "plain", "smtp", "foo", "bar")
	auth_handler := createAuthHandler(func(imap_host, user, pass string) (bool, bool) {
		return true, true
	})

	http_handler(w, r, &auth_handler)

	asserts.AssertEquals(t, "OK", w.Header().Get("Auth-Status"))
	asserts.AssertEquals(t, "smtp.example.org", w.Header().Get("Auth-Server"))
	asserts.AssertEquals(t, "587", w.Header().Get("Auth-Port"))
	asserts.AssertEquals(t, "qq", w.Header().Get("Auth-User"))
	asserts.AssertEquals(t, "pp", w.Header().Get("Auth-Pass"))
}

func createAuthHandler(imapValidator internal.ImapValidator) internal.AuthHandler {
	cfg := internal.Configuration{
		WhitelistedUsers: []string{"foo"},
		ImapServer:       "imap.example.org",
		SmtpServer:       "smtp.example.org",
		SmtpUser:         "qq",
		SmtpPass:         "pp",
	}
	cache_entry_validity, _ := time.ParseDuration("3s")
	return internal.CreateAuthHandlerWithCustomValidator(cfg, imapValidator, cache_entry_validity)
}

func createRequest(attempt int, method, protocol, user, password string) *http.Request {
	r := httptest.NewRequest("GET", "/auth", nil)
	r.Header.Add("Auth-Login-Attempt", strconv.Itoa(attempt))
	addHeaderIfNotEmpty(r, "Auth-Method", method)
	addHeaderIfNotEmpty(r, "Auth-User", user)
	addHeaderIfNotEmpty(r, "Auth-Pass", password)
	addHeaderIfNotEmpty(r, "Auth-Protocol", protocol)
	return r
}

func addHeaderIfNotEmpty(r *http.Request, name, value string) {
	if value != "" {
		r.Header.Add(name, value)
	}
}

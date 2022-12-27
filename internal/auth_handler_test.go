package internal

import (
	"testing"
	"time"

	"github.com/seiferma/nginxmailauthdelegator/internal/asserts"
)

func TestNonWhitelistedCredentialsAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		t.Fatal("should not be called")
		return false, false
	})
	response := handler.HandleAuthRequest("imap", "test", "test", 3)
	asserts.AssertEquals(t, "Invalid login or password", response.Status)
	asserts.AssertEquals(t, "535 5.7.8", response.Error_code)
	asserts.AssertEquals(t, -1, response.Wait)
}

func TestInvalidWhitelistedCredentialsAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})
	response := handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "Invalid login or password", response.Status)
	asserts.AssertEquals(t, "535 5.7.8", response.Error_code)
	asserts.AssertEquals(t, 2, response.Wait)
}

func TestInvalidCredentialsMaxTriesAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		t.Fatal("should not be called")
		return false, false
	})
	response := handler.HandleAuthRequest("imap", "test", "test", 1)
	asserts.AssertEquals(t, "Invalid login or password", response.Status)
	asserts.AssertEquals(t, "535 5.7.8", response.Error_code)
	asserts.AssertEquals(t, 2, response.Wait)
}

func TestValidCredentialsForIMAPAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		return true, true
	})
	response := handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "OK", response.Status)
	asserts.AssertEquals(t, "imap.example.org", response.Server)
	asserts.AssertEquals(t, 993, response.Port)
	asserts.AssertEquals(t, "", response.User)
	asserts.AssertEquals(t, "", response.Password)
}

func TestValidCredentialsForSMTPAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		return true, true
	})
	response := handler.HandleAuthRequest("smtp", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "OK", response.Status)
	asserts.AssertEquals(t, "smtp.example.org", response.Server)
	asserts.AssertEquals(t, 587, response.Port)
	asserts.AssertEquals(t, "barfoo", response.User)
	asserts.AssertEquals(t, "foobar", response.Password)
}

func TestValidCredentialsWithValidHostname(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		return true, true
	})
	handler.smtp_host = "a.root-servers.net"
	response := handler.HandleAuthRequest("smtp", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "OK", response.Status)
	asserts.AssertEquals(t, "198.41.0.4", response.Server)
	asserts.AssertEquals(t, 587, response.Port)
	asserts.AssertEquals(t, "barfoo", response.User)
	asserts.AssertEquals(t, "foobar", response.Password)
}

func TestValidCachedCredentialsAuthHandler(t *testing.T) {
	validator_called := false
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		if validator_called {
			t.Fatal("Validator should not be called twice.")
		}
		return true, true
	})
	response := handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "OK", response.Status)
	response = handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "OK", response.Status)
	asserts.AssertEquals(t, "imap.example.org", response.Server)
	asserts.AssertEquals(t, 993, response.Port)
	asserts.AssertEquals(t, "", response.User)
	asserts.AssertEquals(t, "", response.Password)
}

func TestValidCachedButExpiredCredentialsAuthHandler(t *testing.T) {
	validator_calls := 0
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		validator_calls++
		return true, true
	})
	response := handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "OK", response.Status)

	// wait for cache entry to expire
	time.Sleep(3 * time.Second)

	// try again
	response = handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "OK", response.Status)
	asserts.AssertEquals(t, "imap.example.org", response.Server)
	asserts.AssertEquals(t, 993, response.Port)
	asserts.AssertEquals(t, "", response.User)
	asserts.AssertEquals(t, "", response.Password)

	// assert validator calls
	asserts.AssertEquals(t, 2, validator_calls)
}

func TestInvalidCachedCredentialsAuthHandler(t *testing.T) {
	validator_called := false
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		if validator_called {
			t.Fatal("Validator should not be called twice.")
		}
		return true, true
	})
	response := handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	asserts.AssertEquals(t, "OK", response.Status)
	response = handler.HandleAuthRequest("imap", "test@example.org", "test2", 1)
	asserts.AssertEquals(t, "Invalid login or password", response.Status)
	asserts.AssertEquals(t, "535 5.7.8", response.Error_code)
	asserts.AssertEquals(t, 2, response.Wait)
}

func createAuthHandler(t *testing.T, validator ImapValidator) AuthHandler {
	var cfg Configuration
	err := cfg.Load("testdata/config.yaml")
	asserts.AssertNil(t, err)

	cache_entry_validity, _ := time.ParseDuration("2s")
	handler := CreateAuthHandlerWithCustomCallbacks(cfg, validator, cache_entry_validity)
	asserts.AssertNonNil(t, handler)
	return handler
}

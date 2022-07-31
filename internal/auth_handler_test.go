package internal

import (
	"testing"
	"time"
)

func TestNonWhitelistedCredentialsAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		t.Fatal("should not be called")
		return false, false
	})
	response := handler.HandleAuthRequest("imap", "test", "test", 3)
	assertEquals(t, "Invalid login or password", response.Status)
	assertEquals(t, "535 5.7.8", response.Error_code)
	assertEquals(t, -1, response.Wait)
}

func TestInvalidWhitelistedCredentialsAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		return false, true
	})
	response := handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	assertEquals(t, "Invalid login or password", response.Status)
	assertEquals(t, "535 5.7.8", response.Error_code)
	assertEquals(t, 2, response.Wait)
}

func TestInvalidCredentialsMaxTriesAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		t.Fatal("should not be called")
		return false, false
	})
	response := handler.HandleAuthRequest("imap", "test", "test", 1)
	assertEquals(t, "Invalid login or password", response.Status)
	assertEquals(t, "535 5.7.8", response.Error_code)
	assertEquals(t, 2, response.Wait)
}

func TestValidCredentialsForIMAPAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		return true, true
	})
	response := handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	assertEquals(t, "OK", response.Status)
	assertEquals(t, "imap.example.org", response.Server)
	assertEquals(t, 993, response.Port)
	assertEquals(t, "", response.User)
	assertEquals(t, "", response.Password)
}

func TestValidCredentialsForSMTPAuthHandler(t *testing.T) {
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		return true, true
	})
	response := handler.HandleAuthRequest("smtp", "test@example.org", "test", 1)
	assertEquals(t, "OK", response.Status)
	assertEquals(t, "smtp.example.org", response.Server)
	assertEquals(t, 587, response.Port)
	assertEquals(t, "barfoo", response.User)
	assertEquals(t, "foobar", response.Password)
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
	assertEquals(t, "OK", response.Status)
	response = handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	assertEquals(t, "OK", response.Status)
	assertEquals(t, "imap.example.org", response.Server)
	assertEquals(t, 993, response.Port)
	assertEquals(t, "", response.User)
	assertEquals(t, "", response.Password)
}

func TestValidCachedButExpiredCredentialsAuthHandler(t *testing.T) {
	validator_calls := 0
	handler := createAuthHandler(t, func(imap_host, user, pass string) (bool, bool) {
		validator_calls++
		return true, true
	})
	response := handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	assertEquals(t, "OK", response.Status)

	// wait for cache entry to expire
	time.Sleep(3 * time.Second)

	// try again
	response = handler.HandleAuthRequest("imap", "test@example.org", "test", 1)
	assertEquals(t, "OK", response.Status)
	assertEquals(t, "imap.example.org", response.Server)
	assertEquals(t, 993, response.Port)
	assertEquals(t, "", response.User)
	assertEquals(t, "", response.Password)

	// assert validator calls
	assertEquals(t, 2, validator_calls)
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
	assertEquals(t, "OK", response.Status)
	response = handler.HandleAuthRequest("imap", "test@example.org", "test2", 1)
	assertEquals(t, "Invalid login or password", response.Status)
	assertEquals(t, "535 5.7.8", response.Error_code)
	assertEquals(t, 2, response.Wait)
}

func createAuthHandler(t *testing.T, validator imapValidator) AuthHandler {
	var cfg Configuration
	err := cfg.Load("testdata/config.yaml")
	assertNil(t, err)

	cache_entry_validity, _ := time.ParseDuration("2s")
	handler := createAuthHandlerWithCustomValidator(cfg, validator, cache_entry_validity)
	assertNonNil(t, handler)
	return handler
}

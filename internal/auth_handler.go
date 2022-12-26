package internal

import (
	"time"

	"github.com/emersion/go-imap/client"
	"golang.org/x/crypto/bcrypt"
)

const MAX_RETRIES = 3

type authCacheEntry struct {
	username      string
	password_hash []byte
	expiry        time.Time
}

type ImapValidator func(imap_host, user, pass string) (bool, bool)

type AuthHandler struct {
	valid_usernames      []string
	auth_cache           map[string]authCacheEntry
	cache_entry_validity time.Duration
	imap_host            string
	smtp_host            string
	smtp_user            string
	smtp_password        string
	imap_validator       ImapValidator
}

type AuthResponse struct {
	Status     string
	Error_code string
	Wait       int
	User       string
	Password   string
	Server     string
	Port       int
}

func CreateAuthHandler(cfg Configuration) AuthHandler {
	cache_entry_validity, _ := time.ParseDuration("15m")
	return CreateAuthHandlerWithCustomCallbacks(cfg, credentialsValidInImap, cache_entry_validity)
}

func CreateAuthHandlerWithCustomCallbacks(cfg Configuration, imap_validator ImapValidator, cache_entry_validity time.Duration) AuthHandler {
	return AuthHandler{
		valid_usernames:      cfg.WhitelistedUsers,
		imap_host:            cfg.ImapServer,
		imap_validator:       imap_validator,
		smtp_host:            cfg.SmtpServer,
		smtp_user:            cfg.SmtpUser,
		smtp_password:        cfg.SmtpPass,
		cache_entry_validity: cache_entry_validity,
		auth_cache:           make(map[string]authCacheEntry),
	}
}

func (handler *AuthHandler) HandleAuthRequest(protocol, user, pass string, attempt int) AuthResponse {

	// only proceed if username is whitelisted
	if !contains(handler.valid_usernames, user) {
		return createInvalidCredentialsResponse(attempt)
	}

	// query cache
	password_bytes := []byte(pass)
	decision, valid := handler.credentialsInCacheMatch(user, password_bytes)

	// cache content is invalid, so perform authentication
	if !valid {
		decision, valid = handler.imap_validator(handler.imap_host, user, pass)
		if decision && valid {
			handler.addCredentialsToCache(user, password_bytes)
		}
	}

	if valid && decision {
		return handler.createValidCredentialsResponse(protocol)
	} else {
		return createInvalidCredentialsResponse(attempt)
	}
}

func createInvalidCredentialsResponse(attempt int) AuthResponse {
	response := AuthResponse{
		Status:     "Invalid login or password",
		Error_code: "535 5.7.8",
		Wait:       attempt + 1,
	}
	if attempt >= MAX_RETRIES {
		response.Wait = -1
	}
	return response
}

func (handler *AuthHandler) createValidCredentialsResponse(protocol string) AuthResponse {
	response := AuthResponse{
		Status: "OK",
	}

	if protocol == "imap" {
		response.Server = handler.imap_host
		response.Port = 993
	} else if protocol == "smtp" {
		response.Server = handler.smtp_host
		response.Port = 587
		response.User = handler.smtp_user
		response.Password = handler.smtp_password
	}

	return response
}

// return: bool (decision), bool (decision is valid)
func (handler *AuthHandler) credentialsInCacheMatch(user string, pass []byte) (bool, bool) {
	cache_entry, found_key := handler.auth_cache[user]

	if found_key {

		// key expired -> delete cache entry and exit
		if cache_entry.expiry.Before(time.Now()) {
			delete(handler.auth_cache, user)
			return false, false
		}

		// credentials match credentials stored in cache
		if bcrypt.CompareHashAndPassword(cache_entry.password_hash, pass) == nil {
			return true, true
		}

		// credentials do not match credentials stored in cache
		return false, true
	}

	// no matching entry in cache
	return false, false
}

func (handler *AuthHandler) addCredentialsToCache(user string, pass []byte) error {
	// add entry to cache
	password_hash, err := bcrypt.GenerateFromPassword(pass, 10)
	if err == nil {
		cache_entry := authCacheEntry{
			username:      user,
			password_hash: password_hash,
			expiry:        time.Now().Add(handler.cache_entry_validity),
		}
		handler.auth_cache[user] = cache_entry
	}
	return err
}

// return: bool (decision), bool (decision is valid)
func credentialsValidInImap(imap_host, user, pass string) (bool, bool) {
	client, err := client.DialTLS(imap_host+":993", nil)
	if err != nil {
		return false, false
	}
	defer client.Logout()

	if client.Login(user, pass) != nil {
		return true, true
	} else {
		return false, true
	}
}

func contains(strings []string, search string) bool {
	for _, value := range strings {
		if value == search {
			return true
		}
	}
	return false
}

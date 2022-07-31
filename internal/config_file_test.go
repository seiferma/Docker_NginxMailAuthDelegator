package internal

import (
	"testing"
)

func TestReadingMissingConfigFile(t *testing.T) {
	var cfg Configuration
	err := cfg.Load("testdata/config_doesnotexist.yaml")
	assertNonNil(t, err)
}
func TestReadingBrokenConfigFile(t *testing.T) {
	var cfg Configuration
	err := cfg.Load("testdata/config_brokensyntax.yaml")
	assertNonNil(t, err)
}

func TestReadingConfigFile(t *testing.T) {
	expected_users := [3]string{"some_user", "another_user", "test@example.org"}

	var cfg Configuration
	err := cfg.Load("testdata/config.yaml")

	assertNil(t, err)
	assertStringEquals(t, "imap.example.org", cfg.ImapServer)
	assertStringEquals(t, "smtp.example.org", cfg.SmtpServer)
	assertStringEquals(t, "barfoo", cfg.SmtpUser)
	assertStringEquals(t, "foobar", cfg.SmtpPass)
	assertStringArraysEquals(t, expected_users[:], cfg.WhitelistedUsers)
}

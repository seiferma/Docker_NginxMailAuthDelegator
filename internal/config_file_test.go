package internal

import (
	"testing"

	"github.com/seiferma/nginxmailauthdelegator/internal/asserts"
)

func TestReadingMissingConfigFile(t *testing.T) {
	var cfg Configuration
	err := cfg.Load("testdata/config_doesnotexist.yaml")
	asserts.AssertNonNil(t, err)
}
func TestReadingBrokenConfigFile(t *testing.T) {
	var cfg Configuration
	err := cfg.Load("testdata/config_brokensyntax.yaml")
	asserts.AssertNonNil(t, err)
}

func TestReadingConfigFile(t *testing.T) {
	expected_users := [3]string{"some_user", "another_user", "test@example.org"}

	var cfg Configuration
	err := cfg.Load("testdata/config.yaml")

	asserts.AssertNil(t, err)
	asserts.AssertEquals(t, "imap.example.org", cfg.ImapServer)
	asserts.AssertEquals(t, "smtp.example.org", cfg.SmtpServer)
	asserts.AssertEquals(t, "barfoo", cfg.SmtpUser)
	asserts.AssertEquals(t, "foobar", cfg.SmtpPass)
	asserts.AssertStringArraysEquals(t, expected_users[:], cfg.WhitelistedUsers)
}

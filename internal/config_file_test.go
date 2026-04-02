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
	asserts.AssertEquals(t, 993, cfg.ImapPort)
	asserts.AssertEquals(t, "/etc/ssl/certs/ca-certificates.crt", cfg.CaCertFile)
	asserts.AssertEquals(t, "smtp.example.org", cfg.SmtpServer)
	asserts.AssertEquals(t, "barfoo", cfg.SmtpUser)
	asserts.AssertEquals(t, "foobar", cfg.SmtpPass)
	asserts.AssertStringArraysEquals(t, expected_users[:], cfg.WhitelistedUsers)
}

func TestConfigDefaults(t *testing.T) {
	var cfg Configuration
	// Test that defaults are applied when fields are not set
	cfg.ImapPort = 0
	cfg.CaCertFile = ""
	cfg.applyDefaults()

	asserts.AssertEquals(t, 993, cfg.ImapPort)
	asserts.AssertEquals(t, "/etc/ssl/certs/ca-certificates.crt", cfg.CaCertFile)
}

func TestConfigDefaultsNotOverrideExplicitValues(t *testing.T) {
	var cfg Configuration
	// Test that defaults do not override explicit values
	cfg.ImapPort = 1993
	cfg.CaCertFile = "/custom/path/ca.crt"
	cfg.applyDefaults()

	asserts.AssertEquals(t, 1993, cfg.ImapPort)
	asserts.AssertEquals(t, "/custom/path/ca.crt", cfg.CaCertFile)
}

func TestReadingConfigFileWithCustomValues(t *testing.T) {
	var cfg Configuration
	err := cfg.Load("testdata/config_custom.yaml")

	asserts.AssertNil(t, err)
	asserts.AssertEquals(t, "imap.example.org", cfg.ImapServer)
	asserts.AssertEquals(t, 1993, cfg.ImapPort)
	asserts.AssertEquals(t, "/custom/path/ca.crt", cfg.CaCertFile)
	asserts.AssertEquals(t, "smtp.example.org", cfg.SmtpServer)
	asserts.AssertEquals(t, "barfoo", cfg.SmtpUser)
	asserts.AssertEquals(t, "foobar", cfg.SmtpPass)
}

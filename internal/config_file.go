package internal

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Configuration struct {
	WhitelistedUsers []string `yaml:"users"`
	ImapServer       string   `yaml:"imap_host"`
	ImapPort         int      `yaml:"imap_port"`
	SmtpServer       string   `yaml:"smtp_host"`
	SmtpUser         string   `yaml:"smtp_user"`
	SmtpPass         string   `yaml:"smtp_pass"`
	CaCertFile       string   `yaml:"ca_cert_file"`
}

func (c *Configuration) applyDefaults() {
	if c.ImapPort == 0 {
		c.ImapPort = 993
	}
	if c.CaCertFile == "" {
		c.CaCertFile = "/etc/ssl/certs/ca-certificates.crt"
	}
}

func (c *Configuration) Load(file_path string) error {

	yamlFile, err := ioutil.ReadFile(file_path)
	if err != nil {
		return err
	}
	err = yaml.UnmarshalStrict(yamlFile, c)
	if err != nil {
		return err
	}

	c.applyDefaults()

	return nil
}

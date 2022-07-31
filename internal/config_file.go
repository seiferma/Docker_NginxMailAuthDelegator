package internal

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Configuration struct {
	WhitelistedUsers []string `yaml:"users"`
	ImapServer       string   `yaml:"imap_host"`
	SmtpServer       string   `yaml:"smtp_host"`
	SmtpUser         string   `yaml:"smtp_user"`
	SmtpPass         string   `yaml:"smtp_pass"`
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

	return nil
}

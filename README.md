# Nginx Mail Auth Delegator
[![](https://github.com/seiferma/Docker_NginxMailAuthDelegator/actions/workflows/docker-publish.yml/badge.svg?branch=main)](https://github.com/seiferma/Docker_NginxMailAuthDelegator/actions?query=branch%3Amain+)
[![](https://img.shields.io/github/issues/seiferma/Docker_NginxMailAuthDelegator.svg)](https://github.com/seiferma/Docker_NginxMailAuthDelegator/issues)
[![](https://img.shields.io/github/license/seiferma/Docker_NginxMailAuthDelegator.svg)](https://github.com/seiferma/Docker_NginxMailAuthDelegator/blob/main/LICENSE)

This application implements the [mail authentication protocol](https://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html) of Nginx. It delegates all auth requests for SMTP or IMAP to another IMAP server. This means, an authentication request is granted if the provided credentials are valid to login to the other IMAP server.

To use the application, you have to pass a configuration file as first parameter. An example configuration file looks like this:

```
users:
  - some_user
  - another_user
  - test@example.org
imap_host: imap.example.org
smtp_host: smtp.example.org
smtp_user: barfoo
smtp_pass: foobar
```

| Parameter   | Optional | Meaning                                                                          |
|-------------|----------|----------------------------------------------------------------------------------|
| `users`     | no       | A whitelist of usernames. All other users are denied without further evaluation. |
| `imap_host` | no       | IMAP server to authenticate users and to use if authenticating for IMAP.         |
| `smtp_host` | no       | SMTP server to use if authenticating for SMTP.                                   |
| `smtp_user` | yes      | Username to use to login to SMTP server.                                         |
| `smtp_pass` | yes      | Password to use to login to SMTP server.                                         |

The application caches successful authentications for 15 minutes, i.e. it does not query the IMAP server again for the cached user.
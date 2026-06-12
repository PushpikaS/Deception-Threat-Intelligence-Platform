package main

import "strings"

var weakCredentials = map[string][]string{
	"admin@acmecorp.com":  {"admin", "password", "password123", "Summer2024!", "Acme2024!", "changeme"},
	"root@acmecorp.com":   {"root", "toor", "admin123"},
	"deploy@acmecorp.com": {"deploy", "ci_cd_token", "pipeline"},
	"svc_backup@internal": {"backup2024", "restore_key"},
}

func matchWeakCredential(email, password string) (bool, string) {
	if passwords, ok := weakCredentials[email]; ok {
		for _, p := range passwords {
			if password == p {
				return true, email
			}
		}
	}
	for _, p := range []string{"password", "123456", "admin", "letmein", "qwerty"} {
		if password == p {
			return true, "common_password"
		}
	}
	return false, ""
}

func isEmployeeEmail(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	return strings.HasSuffix(email, "@acmecorp.com") || strings.HasSuffix(email, "@internal")
}
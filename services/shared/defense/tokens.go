package defense

import "strings"

// Canonical deception tokens — discoverable via recon, not advertised in UI.
const (
	OAuthClientID     = "acme-sso-cli"
	OAuthClientSecret = "acme_oauth_cli_secret_9f2a"
	EmployeeInvite    = "ACME-INV-7F3A9B2C"
	MFABackupCode     = "482910"

	LDAPDeployDN      = "cn=deploy,ou=svc,dc=acmecorp,dc=com"
	LDAPDeployPass    = "pipeline"
	FakeJWTMarker     = "acme_jwt_prod_sig_v2"
)

func ValidAPIKey(token string) bool {
	return token == APIKeyFull
}

func ValidOAuthClient(id, secret string) bool {
	return id == OAuthClientID && secret == OAuthClientSecret
}

func ValidInvite(code string) bool {
	return strings.EqualFold(strings.TrimSpace(code), EmployeeInvite)
}

func ValidMFABackup(code string) bool {
	return strings.TrimSpace(code) == MFABackupCode
}

func ValidLDAPBind(dn, password string) bool {
	return strings.EqualFold(strings.TrimSpace(dn), LDAPDeployDN) &&
		strings.TrimSpace(password) == LDAPDeployPass
}
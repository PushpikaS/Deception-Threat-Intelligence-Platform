package defense

import "strings"

// RedactPairs returns secret → redacted mappings derived from canonical bait values.
func RedactPairs() []struct{ Old, New string } {
	return []struct{ Old, New string }{
		{DBPassword, "Sup3r***REDACTED***"},
		{HoneyAWSSecret, "***REDACTED_AWS_SECRET***"},
		{HoneyStripeKey, "sk_live_***REDACTED***"},
		{JWTSecret, "***JWT_REDACTED***"},
		{BackupSQLPassword, "***REDACTED***"},
		{RedisPassword, "***REDACTED***"},
		{HoneyAWSKey, "AKIA***REDACTED***"},
		{HoneyAPIKey, "acme_live_7f3a9b2c***REDACTED***"},
		{OAuthClientSecret, "acme_oauth_cli_***REDACTED***"},
		{EmployeeInvite, "ACME-INV-7F3A***"},
		{MFABackupCode, "482***"},
		{LDAPDeployPass, "***REDACTED***"},
		{LDAPDeployDN, "cn=***REDACTED***"},
		{HoneyGitHubToken, "ghp_***REDACTED***"},
		{WebhookSecret, "whsec_***REDACTED***"},
		{DeployRoleARN, "arn:aws:iam::***REDACTED***"},
	}
}

// RedactSecrets partially redacts bait bodies for tier-1 trap responses.
func RedactSecrets(body string) string {
	out := body
	for _, pair := range RedactPairs() {
		out = strings.ReplaceAll(out, pair.Old, pair.New)
	}
	return out
}
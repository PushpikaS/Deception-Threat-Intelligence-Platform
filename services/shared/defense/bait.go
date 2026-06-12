package defense

import "fmt"

// Canonical honeytoken and bait secret values — single source for all deception services.
const (
	HoneyAWSKey       = "AKIA4ACME7DEPLOY01"
	HoneyAWSSecret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	HoneyStripeKey    = "sk_live_acme_prod_billing_key0a"
	HoneyAPIKey       = "acme_live_7f3a9b2c4d5e6f8a1b2c3d4e5f6a7b8"
	DBPassword        = "Sup3rS3cr3t!"
	RedisPassword     = "r3d1s_p@ss"
	JWTSecret         = "acme_jwt_prod_signing_key_do_not_rotate"
	BackupSQLPassword = "Ch4ng3M3!Now"
	WebhookSecret     = "whsec_acme_prod_webhook_sign9f2a"
	DeployRoleARN     = "arn:aws:iam::123456789012:role/acme-prod-deploy"
	HoneyGitHubToken  = "ghp_acme0ci_readonly_deployment_token012"
)

// APIKeyFull is an alias kept for backward-compatible validators.
const APIKeyFull = HoneyAPIKey

// EnvLeakBody returns the canonical /.env bait payload.
func EnvLeakBody() string {
	return fmt.Sprintf(`APP_ENV=production
APP_DEBUG=false
DATABASE_URL=postgres://acme_app:%s@db.internal.acmecorp.com:5432/acme_prod
REDIS_URL=redis://:%s@cache.internal:6379/0
AWS_ACCESS_KEY_ID=%s
AWS_SECRET_ACCESS_KEY=%s
STRIPE_SECRET_KEY=%s
JWT_SECRET=%s
OAUTH_CLIENT_ID=%s
OAUTH_CLIENT_SECRET=%s
EMPLOYEE_INVITE=%s
MFA_BACKUP_CODE=%s
API_SERVICE_KEY=%s
LDAP_SERVICE_DN=%s
`, DBPassword, RedisPassword, HoneyAWSKey, HoneyAWSSecret, HoneyStripeKey, JWTSecret,
		OAuthClientID, OAuthClientSecret, EmployeeInvite, MFABackupCode, HoneyAPIKey, LDAPDeployDN)
}

// AWSCredentialsBody returns fake ~/.aws/credentials content.
func AWSCredentialsBody() string {
	return fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n",
		HoneyAWSKey, HoneyAWSSecret)
}

// BackupSQLBody returns partial SQL dump bait.
func BackupSQLBody() string {
	return fmt.Sprintf("-- AcmeCorp partial backup 2026-06-01\nCREATE USER acme_admin WITH PASSWORD '%s';\nGRANT ALL ON DATABASE acme_prod TO acme_admin;\nINSERT INTO api_keys (name, key_hash) VALUES ('legacy', '%s');\n",
		BackupSQLPassword, HoneyAPIKey)
}

// ActuatorEnvBody returns Spring actuator env JSON bait.
func ActuatorEnvBody() string {
	return fmt.Sprintf(`{"activeProfiles":["production"],"propertySources":[{"name":"systemEnvironment","properties":{"DATABASE_PASSWORD":{"value":"%s"}}}]}`, DBPassword)
}

// ConfigJSONBody returns /config.json bait.
func ConfigJSONBody() string {
	return fmt.Sprintf(`{"environment":"production","debug":false,"internal_api":"https://api.internal.acmecorp.com","deploy_key":"%s"}`, HoneyAWSKey)
}

// DockerComposeBody returns fake docker-compose bait.
func DockerComposeBody() string {
	return fmt.Sprintf("version: '3.8'\nservices:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: %s\n", DBPassword)
}

// TerraformStateBody returns fake terraform state bait.
func TerraformStateBody() string {
	return fmt.Sprintf(`{"version":4,"resources":[{"type":"aws_instance","instances":[{"attributes":{"public_ip":"203.0.113.10","user_data":"export DB_PASS=%s"}}]}]}`, DBPassword)
}

// APIKeysBackupJSON returns honeyfile api-keys-backup.json body.
func APIKeysBackupJSON() string {
	return fmt.Sprintf(`{"rotated":"2026-01-15","keys":[{"name":"prod-deploy","id":"%s"},{"name":"ci","id":"%s"}]}`, HoneyAWSKey, HoneyAPIKey)
}

// VPNConfigBody returns honeyfile vpn-config.ovpn body.
func VPNConfigBody() string {
	return fmt.Sprintf("client\ndev tun\nremote vpn.internal.acmecorp.com 1194\n# auth-user-pass inline\n# deploy@acmecorp.com\n# %s\n", LDAPDeployPass)
}
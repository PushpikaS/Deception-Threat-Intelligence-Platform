# AcmeCorp Deception Surface Map

This document maps **every deception endpoint** on the public honeypot gateway (`http://localhost:8080`). It is for **red team and security testing** of the fake AcmeCorp environment.

> **Important:** The threat intel dashboard (`http://localhost:9090`) is **not** part of the honeypot. It is a separate, analyst-only system. Attackers probing `:8080` cannot discover or authenticate to `:9090` through normal paths.

---

## Quick reference — analyst test credentials

Use these to verify the **employee → admin** path end-to-end (after any IP lockout clears, or from a fresh IP/incognito session):

| Step | Value |
|------|-------|
| Login URL | `http://localhost:8080/login` |
| Email | `admin@acmecorp.com` |
| Password | `password123` (server accepts any 8+ char password for `*@acmecorp.com` — not advertised on the login form) |
| MFA code | `482910` (6-digit backup code; MFA page shows authenticator-only copy) |
| Result | Redirect to `/admin` with `acme_session` cookie (`role: admin`, 2h TTL) |

**Contractor / viewer path** (storage only, not admin):

| Field | Value |
|-------|-------|
| Register URL | `http://localhost:8080/register` |
| Invite code | `ACME-INV-7F3A9B2C` (discoverable via `/.env` or recon) |
| Result | `role: viewer` session → `/storage/` |

---

## Architecture (what attackers see)

Attackers only interact with the **deception gateway** (`nginx-honeypot` on `:8080`). Intelligence services run on an isolated internal network with no public ports.

```
Attacker → nginx-honeypot :8080
              ├── honeypot-auth   (login, MFA, OAuth, LDAP, register)
              ├── honeypot-web    (admin UI, traps, fake apps, exports)
              └── honeypot-api    (fake REST /api/v1/*)
                    ↓ XADD
              redis-events (stream: honeypot:events)
                    ↓
              threat-ingest → postgres-events
                    ↓
              threat-engine → postgres-intel
                    ↓
              threat-api + redis-platform → dashboard :9090 (private)
```

**Data isolation:** honeypot sessions live in `redis-defense`; the analyst dashboard uses `redis-platform` and separate Postgres databases. Attackers cannot reach any of these directly.

Every HTTP request to deception endpoints is logged and classified. Repeated abuse triggers **WAF blocks**, **login lockouts**, and **MFA lockouts**.

**Realism note:** Login pages, API error JSON, and register flows use generic corporate messaging. There are no `hint` fields or on-screen password rules. Progression requires recon (`.env`, misconfigured admin pages, LDAP/OAuth grants) — not UI hand-holding.

---

## 1. Reconnaissance & scanner traps

Automated scanners and curious browsers often hit these paths first. Many return **fake leaks** (honeytokens) designed to look like misconfigurations.

| Path | Trap name | Typical response | Sensitive? |
|------|-----------|------------------|------------|
| `/.env` | `env_leak` | Fake DB URLs, AWS keys, OAuth secrets, MFA code, invite code | Yes |
| `/.aws/credentials` | `env_leak` | Fake AWS access key pair | Yes |
| `/.git/HEAD` | `git_exposure` | Fake git ref | Yes |
| `/.git/config` | `git_exposure` | Fake internal git remote | Yes |
| `/backup.sql` | `backup_leak` | Fake SQL dump with passwords | Yes |
| `/robots.txt` | `robots` | Disallow rules pointing to `/admin`, `/.env`, `/api/v1/internal/` | No |
| `/sitemap.xml` | `sitemap` | Links to `/login`, `/admin`, `/api/v1/docs`, `/api/v1/internal/debug` | No |
| `/.well-known/security.txt` | `security_txt` | security@acmecorp.com | No |
| `/actuator/health` | `actuator_probe` | Fake Spring Boot health JSON | No |
| `/actuator/env` | `actuator_probe` | Fake env with DB password | Yes |
| `/swagger.json` | `swagger_probe` | OpenAPI listing internal/debug paths | No |
| `/server-status` | `apache_status` | Fake Apache status page | No |
| `/config.json` | `config_leak` | Fake production config + deploy key | Yes |
| `/debug/pprof/` | `pprof_probe` | Fake Go pprof index | Yes |
| `/docker-compose.yml` | `config_leak` | Fake compose with postgres password | Yes |
| `/terraform.tfstate` | `backup_leak` | Fake TF state with secrets | Yes |
| `/package.json` | `config_leak` | Fake Node project metadata | No |
| `/status` | (status page) | Public status board; links to login, SSO, API docs | No |

**WAF behavior:** Sensitive traps use a 3-tier model (`defense.Guard.ResolveTrapTier`):

- **Tier 0** — Too many probes from one IP → `403` WAF block
- **Tier 1** — Partial/redacted body (`RedactSecrets`)
- **Tier 2** — Full bait content (after enough recon activity)

---

## 2. Authentication surfaces

### 2.1 Employee login (primary path to admin)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/login` | GET | Login HTML — "Sign in with your organization account" |
| `/auth/login` | POST | JSON login; advances to MFA for `*@acmecorp.com` + password ≥ 8 chars (server-side) |
| `/login/mfa` | GET | MFA HTML form |
| `/auth/mfa/verify` | POST | MFA verification; issues admin session on valid backup code |

**Accepted employee emails:** `*@acmecorp.com`, `*@internal`

**Known weak passwords** (logged as `weak_credential_attempt`):

- `admin@acmecorp.com`: `admin`, `password`, `password123`, `Summer2024!`, `Acme2024!`, `changeme`
- Common: `password`, `123456`, `admin`, `letmein`, `qwerty`

**Lockouts:**

- 5 failed logins → `ACCOUNT_LOCKED` for 15 minutes
- 5 failed MFA attempts → `MFA_LOCKED` for 10 minutes

### 2.2 SSO / OAuth

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/login/sso?provider=okta` | GET | Fake SSO page |
| `/auth/oauth/callback` | GET | OAuth callback; requires `client_id=acme-sso-cli` + email + state |

**Secrets (from `/.env` or traps):**

```
OAUTH_CLIENT_ID=acme-sso-cli
OAUTH_CLIENT_SECRET=acme_oauth_cli_secret_9f2a
```

Successful SSO → `{"status":"mfa_required","next":"/login/mfa"}` → complete MFA at `/login/mfa`.

### 2.3 Contractor registration (viewer role)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/register` | GET | Registration HTML |
| `/auth/register` | POST | Submit email + invite code |

**Valid invite:** `ACME-INV-7F3A9B2C` → `role: viewer`, scopes `storage:read`, `status:read`. **Does not grant `/admin`.**

### 2.4 LDAP bind (service token pivot)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/ldap/bind` | POST | LDAP bind simulation |

**Valid bind** (from `/.env`):

```
dn:       cn=deploy,ou=svc,dc=acmecorp,dc=com
password: pipeline
```

**Success:** Issues Bearer token (`atk_...`) for gated API routes. Marks IP for `ldap_pivot` classification. No `hint` fields in the JSON response.

### 2.5 Password reset (noise / social engineering)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/forgot-password` | GET | Reset form |
| `/auth/forgot-password` | POST | Always returns “reset link sent” (no real reset) |

### 2.6 Session management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/session` | GET | Returns current session role |
| `/auth/logout` | GET | Invalidates Redis session, clears cookies, redirect `/login` |

**Session cookie:** `acme_session` (HttpOnly, 2h). **Decoy cookie:** `acme_jwt` (fake JWT honeytoken).

---

## 3. Admin console (requires admin session)

All routes redirect to `/login?redirect=...` without `role: admin`.

| Path | Content |
|------|---------|
| `/admin` | System dashboard |
| `/admin/users` | User management table |
| `/admin/settings` | Org settings + embedded secrets (webhook key, API key, AWS ARN) |
| `/admin/logs` | Audit log viewer |
| `/admin/billing` | Fake billing / invoices |
| `/admin/api-keys` | Fake API key management |
| `/admin/security` | Security posture summary |
| `/admin/integrations` | SSO/billing/Slack integration table |
| `/admin/api/keys` | JSON API keys endpoint (401 without session) |
| `/static/admin.js` | Admin UI JavaScript |

**Sign out:** Sidebar link → `/auth/logout`

---

## 4. Fake internal applications

Require **viewer or admin** session; otherwise `302` → `/login?redirect=...` (or WAF `403` on sensitive paths).

| Path | Trap | Simulates |
|------|------|-----------|
| `/jenkins`, `/jenkins/login` | `jenkins_probe` | Jenkins login |
| `/jira`, `/jira/login` | `jira_probe` | Jira login |
| `/confluence`, `/confluence/login` | `confluence_probe` | Confluence login |
| `/grafana`, `/grafana/login` | `grafana_probe` | Grafana login |
| `/storage/` | `storage_browser` | S3-style file browser |
| `/upload` | (public) | Support file upload form |
| `/upload/submit` | POST | Accepts upload metadata (202 queued) |
| `/error?code=500` | `error_leak` | Stack trace with DB URL + JWT secret (after probe threshold) |

**Export artifacts** (require viewer/admin session):

| Path | File |
|------|------|
| `/downloads/exports/employee-export.csv` | Employee email list |
| `/downloads/exports/vpn-config.ovpn` | VPN profile (inline comments reference deploy account) |
| `/downloads/exports/api-keys-backup.json` | Fake API key backup |
| `/downloads/exports/payroll-q2.xlsx` | Always `403` — restricted object |

---

## 5. Legacy / CMS traps

| Path | Trap | Notes |
|------|------|-------|
| `/wp-admin/` | `wordpress_probe` | Fake WordPress admin |
| `/wp-admin/login.php` | `wordpress_login` | POST captures credentials |
| `/phpmyadmin/` | `phpmyadmin_probe` | Fake phpMyAdmin UI |
| `/phpmyadmin/index.php` | POST | Captures DB login attempts |

---

## 6. REST API (`/api/v1/*`)

Base: `http://localhost:8080/api/v1/`

### 6.1 Open / low-friction endpoints

| Method | Path | Behavior |
|--------|------|----------|
| GET | `/users` | Fake user list |
| GET | `/users/{id}` | Fake user detail |
| GET | `/search?q=` | Search; **SQLi/XSS/RCE patterns in `q` are logged** |
| GET | `/config` | Public config; adds `_deploy_key` if session exists |
| GET | `/orders` | Fake orders |
| POST | `/orders` | Accepts order (202) |
| GET | `/webhooks` | Lists webhooks (includes fake Stripe secret) |
| POST | `/webhooks` | Register webhook; **honeytoken in body triggers detection** |
| GET | `/ldap/users` | LDAP directory enumeration bait |
| GET | `/billing/invoices` | Fake invoices |
| GET | `/health` | API health JSON |
| GET | `/metrics` | Fake metrics |
| POST | `/upload` | Accepts upload metadata |
| GET | `/files` | Fake document list |
| GET | `/docs` | HTML API documentation |
| POST | `/graphql` | GraphQL introspection bait |
| GET | `/secrets` | `403` — generic access denied |
| POST | `/users` | `403` — employee provisioning disabled |

### 6.2 Gated / privilege-escalation endpoints

| Method | Path | Requirement |
|--------|------|-------------|
| GET | `/internal/debug` | Bearer token (OAuth or LDAP) + probe tier; returns debug config including keys |
| GET | `/admin/export` | Admin session + weak-credential flag or repeated probes |
| GET | `/me` | Any valid session (returns role/email) |
| POST | `/auth/token` | OAuth `client_credentials` or LDAP password grant |

**OAuth token grant** (`POST /api/v1/auth/token`):

```json
{
  "grant_type": "client_credentials",
  "client_id": "acme-sso-cli",
  "client_secret": "acme_oauth_cli_secret_9f2a"
}
```

**LDAP password grant:**

```json
{
  "grant_type": "password",
  "username": "cn=deploy,ou=svc,dc=acmecorp,dc=com",
  "password": "pipeline"
}
```

Use returned `access_token` as `Authorization: Bearer atk_...` on `/api/v1/internal/debug`.

Forbidden responses use generic `message` / `error_description` fields — no `hint` keys.

---

## 7. Attack chains (multi-stage progression)

### Chain A — Employee to admin (intended analyst path)

```
/login → POST /auth/login (admin@acmecorp.com / password123)
       → /login/mfa → POST /auth/mfa/verify (482910)
       → /admin
```

Classified as `benign_session` when completed normally.

### Chain B — Recon to secrets

```
/.env or /robots.txt → discover paths & secrets
       → use MFA_BACKUP_CODE / OAUTH_CLIENT_* / EMPLOYEE_INVITE
```

Classifications: `env_leak`, `config_leak`, `honeytoken_trigger`, `reconnaissance`.

### Chain C — OAuth / LDAP to internal API

```
/.env → OAUTH_CLIENT_ID + SECRET
      → POST /api/v1/auth/token (client_credentials)
      → GET /api/v1/internal/debug (Bearer)
```

Or:

```
/.env → LDAP_SERVICE_DN + password
      → POST /auth/ldap/bind
      → GET /api/v1/internal/debug (Bearer)
```

Classifications: `ldap_pivot`, `oauth_misconfig`, `config_leak`.

### Chain D — Contractor to storage

```
/register → POST /auth/register (invite ACME-INV-7F3A9B2C)
          → /storage/ → export downloads
```

Classifications: `registration_bypass`, `honeytoken_trigger` (if keys exfiltrated).

### Chain E — Automated attacks (no auth)

```
Brute force POST /auth/login          → brute_force
Many emails POST /auth/login          → credential_stuffing
sqlmap UA + /api/v1/users             → scanner_tool
/api/v1/search?q=' OR 1=1--           → sqli_attempt
/api/v1/search?q=;cat /etc/passwd     → rce_attempt
POST webhook with AKIA... key         → honeytoken_trigger
Rapid path scanning                   → port_scanner / cross_service_probe
```

Run `scripts/simulate-attacks.ps1` to trigger most of these.

---

## 8. Honeytokens (fake credentials that trigger detections)

These are **decoy secrets** planted in traps and responses. When an attacker uses or exfiltrates them, `threat-engine` records a classification.

| Token | Where found | Classification |
|-------|-------------|----------------|
| `AKIA4ACME7DEPLOY01` | `.env`, config, admin settings, API responses | `honeytoken_trigger` |
| `acme_live_7f3a9b2c4d5e6f8a1b2c3d4e5f6a7b8` | `.env`, settings, export files | `honeytoken_trigger` |
| `sk_live_acme_prod_billing_key0a` | webhooks, `.env` | `honeytoken_trigger` |
| `acme_oauth_cli_secret_9f2a` | `.env` | `oauth_misconfig` when used |
| `482910` | `.env` (MFA_BACKUP_CODE) | Used in MFA flow (`benign_session` when analyst path) |
| `ACME-INV-7F3A9B2C` | `.env` | `registration_bypass` |
| `pipeline` / LDAP DN | `.env`, vpn config | `ldap_pivot` |

---

## 9. What attackers cannot reach

| Target | Why |
|--------|-----|
| Dashboard `:9090` | Separate nginx gateway; not linked from honeypot |
| `postgres-events` / `postgres-intel` | Internal Docker network only; split databases |
| `redis-events` / `redis-defense` / `redis-platform` | Internal only; no host ports |
| `threat-ingest` / `threat-engine` / `threat-api` | No public ports |
| Other tenants' sessions | Sessions stored per-token in `redis-defense`; cryptographically random |

---

## 10. Verifying your attacks were captured

The analyst dashboard (`http://localhost:9090`) is on a **separate gateway** from the honeypot. It does not expose honeypot paths and is not discoverable from `:8080`.

1. Wait ~2 seconds (`threat-ingest` writes events; `threat-engine` classifies on the next 2s poll).
2. Open `http://localhost:9090` → sign in (`analyst` / `changeme_local_only`).
3. Confirm captures across dashboard sections:

| Section | What to look for |
|---------|------------------|
| **System Health** | `engine_lag` near 0; postgres/redis healthy |
| **Event Stream** | Your probe with event-local classification + MITRE |
| **Attacker Profiles** | IP risk score, geo (MaxMind or IP-API), behavior tags |
| **Top Attacking Countries** | Country volume if public IPs were used |
| **ASN Rollup** | ASN/org rollup from GeoIP enrichment |
| **Threat Map** | Verified geo pins with accuracy rings |
| **Attack Timeline / Heatmap** | Volume and classification spread |
| **Attack Chains** | Cross-service sequences (auth + web + API) |
| **Profile modal** | STIX export, per-IP blocklist (`min_risk` threshold in UI) |

**Geo note:** Local Docker traffic uses private IPs unless you spoof a public address. `scripts/simulate-attacks.ps1` sends `X-Forwarded-For` with real public IPs so country/map data populates in dev.

**Live updates:** The dashboard polls every 10s and also listens on WebSocket `ws://localhost:9090/api/ws/live` for instant refresh when the engine publishes to Redis `tip:live`.

Or via API (cookie session — recommended):

```powershell
# Login and save cookie
$body = '{"username":"analyst","password":"changeme_local_only"}'
$body | Set-Content $env:TEMP\hp-login.json -NoNewline
curl.exe -c $env:TEMP\hp-cookies.txt -X POST -H "Content-Type: application/json" `
  -d "@$env:TEMP\hp-login.json" http://localhost:9090/api/auth/login

curl.exe -b $env:TEMP\hp-cookies.txt http://localhost:9090/api/health/platform
curl.exe -b $env:TEMP\hp-cookies.txt "http://localhost:9090/api/events?limit=20"
```

HTTP Basic Auth (`curl -u analyst:...`) also works for scripts.

---

## 11. Simulation and verification commands

```powershell
# Full attack pattern simulation (honeypot only)
.\scripts\simulate-attacks.ps1

# Quick smoke test
.\scripts\test-smoke.ps1

# Every dashboard + honeypot endpoint (104 checks)
.\scripts\test-all-endpoints.ps1

# Production + microservice health + deception realism checks
.\scripts\verify-production.ps1
```

**Recommended full audit sequence** (after `docker compose up -d`):

```powershell
.\scripts\simulate-attacks.ps1
Start-Sleep -Seconds 2
.\scripts\test-all-endpoints.ps1
.\scripts\verify-production.ps1
```

---
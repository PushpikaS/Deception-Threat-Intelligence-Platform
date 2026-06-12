# Full endpoint verification — dashboard API + honeypot deception surfaces
$ErrorActionPreference = "Stop"
$dash = "http://localhost:9090"
$hp = "http://localhost:8080"
$dashUser = if ($env:DASHBOARD_AUTH_USER) { $env:DASHBOARD_AUTH_USER } else { "analyst" }
$dashPass = if ($env:DASHBOARD_AUTH_PASS) { $env:DASHBOARD_AUTH_PASS } else { "changeme_local_only" }
$cookieJar = Join-Path $env:TEMP "hp-all-endpoints-cookies.txt"
$passed = 0
$failed = 0

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [int[]]$Allowed = @(200),
        [string]$Method = "GET",
        [string]$CookieJar = $null,
        [switch]$SaveCookies,
        [string]$BodyFile = $null
    )
    $args = @("-o", "NUL", "-w", "%{http_code}", "-X", $Method)
    if ($CookieJar -and $SaveCookies) { $args = @("-c", $CookieJar, "-b", $CookieJar) + $args }
    elseif ($CookieJar) { $args = @("-b", $CookieJar) + $args }
    if ($BodyFile) { $args += @("-H", "Content-Type: application/json", "-d", "@$BodyFile") }
    $code = [int](& curl.exe @args $Url)
    if ($code -notin $Allowed) {
        Write-Host "FAIL $Name -> $Url (HTTP $code, expected $($Allowed -join '|'))" -ForegroundColor Red
        $script:failed++
        return
    }
    Write-Host "OK   $Name ($code)" -ForegroundColor Green
    $script:passed++
}

if (Test-Path $cookieJar) { Remove-Item $cookieJar -Force }
$loginBodyPath = Join-Path $env:TEMP "hp-all-login.json"
@{ username = $dashUser; password = $dashPass } | ConvertTo-Json -Compress | Set-Content -Path $loginBodyPath -Encoding UTF8 -NoNewline

Write-Host "=== Dashboard API (cookie auth) ===" -ForegroundColor Cyan

Test-Endpoint "health" "$dash/api/health" -Allowed @(200)
Test-Endpoint "auth/config" "$dash/api/auth/config" -Allowed @(200)

$loginOk = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
    $loginCode = [int](& curl.exe -c $cookieJar -b $cookieJar -o NUL -w "%{http_code}" `
        -X POST -H "Content-Type: application/json" -d "@$loginBodyPath" "$dash/api/auth/login")
    if ($loginCode -eq 200) {
        Write-Host "OK   auth/login ($loginCode)" -ForegroundColor Green
        $passed++
        $loginOk = $true
        break
    }
    if ($loginCode -eq 429 -and $attempt -lt 5) {
        Write-Host "WAIT auth/login rate limited (429), retry $attempt/5..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        continue
    }
    Write-Host "FAIL auth/login -> $dash/api/auth/login (HTTP $loginCode, expected 200)" -ForegroundColor Red
    $failed++
    break
}
if (-not $loginOk) {
    Write-Host "`nDashboard login failed - skipping authed API checks." -ForegroundColor Red
    exit 1
}
Test-Endpoint "auth/session" "$dash/api/auth/session" -CookieJar $cookieJar
Test-Endpoint "auth/me" "$dash/api/auth/me" -CookieJar $cookieJar
Test-Endpoint "health/platform" "$dash/api/health/platform" -CookieJar $cookieJar
Test-Endpoint "stats/overview" "$dash/api/stats/overview" -CookieJar $cookieJar
Test-Endpoint "stats/trends" "$dash/api/stats/trends" -CookieJar $cookieJar
Test-Endpoint "stats/countries" "$dash/api/stats/countries?limit=8&hours=24" -CookieJar $cookieJar
Test-Endpoint "stats/asn" "$dash/api/stats/asn?limit=10" -CookieJar $cookieJar
Test-Endpoint "events" "$dash/api/events?limit=10" -CookieJar $cookieJar
Test-Endpoint "profiles/search" "$dash/api/profiles/search?limit=10" -CookieJar $cookieJar
Test-Endpoint "search" "$dash/api/search?q=test" -CookieJar $cookieJar
Test-Endpoint "chains" "$dash/api/chains" -CookieJar $cookieJar
Test-Endpoint "timeline" "$dash/api/timeline?hours=24" -CookieJar $cookieJar
Test-Endpoint "heatmap" "$dash/api/heatmap?hours=24" -CookieJar $cookieJar
Test-Endpoint "map" "$dash/api/map" -CookieJar $cookieJar
Test-Endpoint "mitre/map" "$dash/api/mitre/map" -CookieJar $cookieJar
Test-Endpoint "taxonomy" "$dash/api/taxonomy" -CookieJar $cookieJar
Test-Endpoint "export/events.csv" "$dash/api/export/events.csv" -CookieJar $cookieJar
Test-Endpoint "export/profiles.csv" "$dash/api/export/profiles.csv" -CookieJar $cookieJar
Test-Endpoint "export/blocklist.txt" "$dash/api/export/blocklist.txt?min_risk=0" -CookieJar $cookieJar
Test-Endpoint "unauth blocked" "$dash/api/stats/overview" -Allowed @(401)

$profileIp = (& curl.exe -b $cookieJar "$dash/api/profiles/search?limit=1" | ConvertFrom-Json | Select-Object -First 1).ip
if ($profileIp) {
    Test-Endpoint "profiles/{ip}" "$dash/api/profiles/$profileIp" -CookieJar $cookieJar
    Test-Endpoint "profiles/{ip}/timeline" "$dash/api/profiles/$profileIp/timeline?hours=24" -CookieJar $cookieJar
    Test-Endpoint "export/stix/{ip}" "$dash/api/export/stix/$profileIp" -CookieJar $cookieJar
    Test-Endpoint "export/blocklist/{ip}" "$dash/api/export/blocklist/$profileIp" -CookieJar $cookieJar
} else {
    Write-Host "SKIP profile detail endpoints (no profiles yet - run simulate-attacks.ps1)" -ForegroundColor Yellow
}

Test-Endpoint "auth/logout" "$dash/api/auth/logout" -Method POST -CookieJar $cookieJar -Allowed @(200)

Write-Host "`n=== Honeypot auth ===" -ForegroundColor Cyan
Test-Endpoint "login page" "$hp/login"
Test-Endpoint "register page" "$hp/register"
Test-Endpoint "forgot-password" "$hp/forgot-password"
Test-Endpoint "login/mfa" "$hp/login/mfa"
Test-Endpoint "login/sso" "$hp/login/sso?provider=okta"
Test-Endpoint "auth/session" "$hp/auth/session" -Allowed @(200, 401)
Test-Endpoint "auth/logout" "$hp/auth/logout" -Allowed @(302, 303)
Test-Endpoint "health" "$hp/health" -Allowed @(200)

$hpLoginPath = Join-Path $env:TEMP "hp-test-login.json"
'{"email":"probe@evil.com","password":"wrongpass"}' | Set-Content -Path $hpLoginPath -Encoding UTF8 -NoNewline
Test-Endpoint "auth/login POST" "$hp/auth/login" -Method POST -BodyFile $hpLoginPath -Allowed @(200, 401, 403, 429)

$hpRegisterPath = Join-Path $env:TEMP "hp-test-register.json"
'{"email":"contractor@external.com","invite_code":"INVALID"}' | Set-Content -Path $hpRegisterPath -Encoding UTF8 -NoNewline
Test-Endpoint "auth/register POST" "$hp/auth/register" -Method POST -BodyFile $hpRegisterPath -Allowed @(200, 400, 403)

$hpLdapPath = Join-Path $env:TEMP "hp-test-ldap.json"
'{"dn":"cn=probe,dc=evil,dc=com","password":"wrong"}' | Set-Content -Path $hpLdapPath -Encoding UTF8 -NoNewline
Test-Endpoint "auth/ldap/bind POST" "$hp/auth/ldap/bind" -Method POST -BodyFile $hpLdapPath -Allowed @(200, 401, 403)

Test-Endpoint "auth/oauth/callback" "$hp/auth/oauth/callback?client_id=acme-sso-cli&email=admin@acmecorp.com&state=abc" -Allowed @(200, 302, 400)

$hpForgotPath = Join-Path $env:TEMP "hp-test-forgot.json"
'{"email":"probe@evil.com"}' | Set-Content -Path $hpForgotPath -Encoding UTF8 -NoNewline
Test-Endpoint "auth/forgot-password POST" "$hp/auth/forgot-password" -Method POST -BodyFile $hpForgotPath -Allowed @(200, 202)

Write-Host "`n=== Honeypot traps ===" -ForegroundColor Cyan
$traps = @(
    "/.env", "/.git/HEAD", "/.git/config", "/backup.sql", "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt", "/actuator/health", "/actuator/env", "/swagger.json",
    "/server-status", "/config.json", "/debug/pprof/", "/.aws/credentials",
    "/docker-compose.yml", "/terraform.tfstate", "/package.json", "/status"
)
foreach ($t in $traps) {
    Test-Endpoint "trap $t" "$hp$t" -Allowed @(200, 403)
}

Write-Host "`n=== Honeypot admin and apps ===" -ForegroundColor Cyan
$admin = @("/admin", "/admin/users", "/admin/settings", "/admin/logs", "/admin/billing", "/admin/api-keys", "/admin/security", "/admin/integrations")
foreach ($a in $admin) {
    Test-Endpoint "admin $a" "$hp$a" -Allowed @(200, 302)
}
$apps = @("/jenkins", "/jira", "/confluence", "/grafana", "/storage/", "/upload", "/wp-admin/", "/phpmyadmin/")
foreach ($a in $apps) {
    Test-Endpoint "app $a" "$hp$a" -Allowed @(200, 302, 403)
}
Test-Endpoint "honeyfile csv" "$hp/downloads/exports/employee-export.csv" -Allowed @(200, 302, 401, 403)
Test-Endpoint "honeyfile vpn" "$hp/downloads/exports/vpn-config.ovpn" -Allowed @(200, 302, 401, 403)
Test-Endpoint "honeyfile keys" "$hp/downloads/exports/api-keys-backup.json" -Allowed @(200, 302, 401, 403)
Test-Endpoint "honeyfile payroll locked" "$hp/downloads/exports/payroll-q2.xlsx" -Allowed @(403)
Test-Endpoint "static admin.js" "$hp/static/admin.js" -Allowed @(200)
Test-Endpoint "admin/api/keys" "$hp/admin/api/keys" -Allowed @(200, 401, 302)
Test-Endpoint "upload/submit" "$hp/upload/submit" -Method POST -Allowed @(200, 202, 302, 400)
Test-Endpoint "error leak" "$hp/error?code=500" -Allowed @(200, 500)

Write-Host "`n=== Honeypot API v1 ===" -ForegroundColor Cyan
$api = @(
    "/api/v1/users", "/api/v1/search?q=test", "/api/v1/config", "/api/v1/orders",
    "/api/v1/webhooks", "/api/v1/ldap/users", "/api/v1/billing/invoices",
    "/api/v1/health", "/api/v1/metrics", "/api/v1/files", "/api/v1/docs",
    "/api/v1/secrets", "/api/v1/me", "/api/v1/internal/debug", "/api/v1/admin/export"
)
foreach ($a in $api) {
    Test-Endpoint "api $a" "$hp$a" -Allowed @(200, 401, 403, 404)
}

Test-Endpoint "api /api/v1/users/1" "$hp/api/v1/users/1" -Allowed @(200)

$graphqlBodyPath = Join-Path $env:TEMP "hp-graphql.json"
'{"query":"{ __schema { types { name } } }"}' | Set-Content -Path $graphqlBodyPath -Encoding UTF8 -NoNewline
Test-Endpoint "api /api/v1/graphql" "$hp/api/v1/graphql" -Method POST -BodyFile $graphqlBodyPath -Allowed @(200, 400)

$orderBodyPath = Join-Path $env:TEMP "hp-order.json"
'{"sku":"SKU-1001","qty":1}' | Set-Content -Path $orderBodyPath -Encoding UTF8 -NoNewline
Test-Endpoint "api POST /api/v1/orders" "$hp/api/v1/orders" -Method POST -BodyFile $orderBodyPath -Allowed @(200, 202)

$webhookBodyPath = Join-Path $env:TEMP "hp-webhook.json"
'{"url":"https://hooks.example.com/in","events":["order.created"]}' | Set-Content -Path $webhookBodyPath -Encoding UTF8 -NoNewline
Test-Endpoint "api POST /api/v1/webhooks" "$hp/api/v1/webhooks" -Method POST -BodyFile $webhookBodyPath -Allowed @(200, 201)

$uploadBodyPath = Join-Path $env:TEMP "hp-upload.json"
'{"filename":"probe.txt","size":128}' | Set-Content -Path $uploadBodyPath -Encoding UTF8 -NoNewline
Test-Endpoint "api POST /api/v1/upload" "$hp/api/v1/upload" -Method POST -BodyFile $uploadBodyPath -Allowed @(200, 202)

$tokenBodyPath = Join-Path $env:TEMP "hp-token.json"
'{"grant_type":"client_credentials","client_id":"acme-sso-cli","client_secret":"wrong"}' | Set-Content -Path $tokenBodyPath -Encoding UTF8 -NoNewline
Test-Endpoint "api POST /api/v1/auth/token" "$hp/api/v1/auth/token" -Method POST -BodyFile $tokenBodyPath -Allowed @(200, 401, 403)

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Passed: $passed" -ForegroundColor Green
if ($failed -gt 0) {
    Write-Host "Failed: $failed" -ForegroundColor Red
    exit 1
}
Write-Host "All endpoint tests passed." -ForegroundColor Green
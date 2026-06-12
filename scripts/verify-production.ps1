# Production readiness verification — auth, secrets, trap registry, endpoints
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dash = "http://localhost:9090"
$hp = "http://localhost:8080"
$dashUser = if ($env:DASHBOARD_AUTH_USER) { $env:DASHBOARD_AUTH_USER } else { "analyst" }
$dashPass = if ($env:DASHBOARD_AUTH_PASS) { $env:DASHBOARD_AUTH_PASS } else { "changeme_local_only" }
$auth = "-u", "${dashUser}:${dashPass}"
$cookieJar = Join-Path $env:TEMP "hp-verify-cookies.txt"

Write-Host "=== Static checks ===" -ForegroundColor Cyan

$registry = Join-Path $root "shared\trap_registry.json"
if (-not (Test-Path $registry)) { throw "Missing trap registry: $registry" }
$reg = Get-Content $registry -Raw | ConvertFrom-Json
$trapCount = @($reg.trap_rules.PSObject.Properties).Count
Write-Host "OK trap_registry.json loaded ($trapCount trap rules)"

$bait = Join-Path $root "services\shared\defense\bait.go"
$baitText = Get-Content $bait -Raw
foreach ($token in @("HoneyAWSKey", "HoneyAPIKey", "HoneyStripeKey", "DBPassword", "JWTSecret")) {
    if ($baitText -notmatch $token) { throw "bait.go missing canonical $token" }
}
Write-Host "OK defense/bait.go canonical honeytokens present"

$apiJs = Join-Path $root "frontend\src\api.js"
$apiText = Get-Content $apiJs -Raw
if ($apiText -match 'sessionStorage\.setItem\(AUTH_KEY') { throw "frontend still stores credentials in sessionStorage" }
if ($apiText -notmatch "credentials: 'include'") { throw "frontend fetch missing credentials: include" }
Write-Host "OK dashboard session auth configured"

$loginHtml = & curl.exe "$hp/login"
foreach ($bad in @("Minimum 8", "backup code", "credential_hint", "CTF")) {
    if ($loginHtml -match [regex]::Escape($bad)) { throw "Login page contains lab copy: $bad" }
}
Write-Host "OK honeypot login page has no lab hand-holding copy"

$oauthBody = & curl.exe "$hp/auth/oauth/callback?client_id=acme-sso-cli&email=admin@acmecorp.com&state=abc"
if ($oauthBody -match '"hint"') { throw "OAuth callback still returns hint fields" }
Write-Host "OK honeypot API responses avoid CTF hint fields"

Write-Host "`n=== Microservice health ===" -ForegroundColor Cyan

$healthPath = Join-Path $env:TEMP "hp-verify-health.json"
$healthOk = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
    $healthCode = [int](& curl.exe -o $healthPath -w "%{http_code}" "$dash/api/health")
    if ($healthCode -eq 200) {
        $healthOk = $true
        break
    }
    if ($healthCode -eq 429 -and $attempt -lt 5) {
        Write-Host "WAIT /api/health rate limited (429), retry $attempt/5..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        continue
    }
    throw "/api/health returned HTTP $healthCode"
}
$health = Get-Content $healthPath -Raw | ConvertFrom-Json
if ($health.checks.postgres_events -ne "ok") { throw "postgres_events unhealthy: $($health.checks.postgres_events)" }
if ($health.checks.postgres_intel -ne "ok") { throw "postgres_intel unhealthy: $($health.checks.postgres_intel)" }
if ($health.checks.redis_platform -ne "ok") { throw "redis_platform unhealthy: $($health.checks.redis_platform)" }
Write-Host "OK /api/health - postgres_events, postgres_intel, redis_platform"

Write-Host "`n=== Dashboard auth ===" -ForegroundColor Cyan

if (Test-Path $cookieJar) { Remove-Item $cookieJar -Force }

$loginBodyPath = Join-Path $env:TEMP "hp-login-body.json"
@{ username = $dashUser; password = $dashPass } | ConvertTo-Json -Compress | Set-Content -Path $loginBodyPath -Encoding UTF8 -NoNewline

$loginOk = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
    $loginCode = [int](& curl.exe -c $cookieJar -b $cookieJar -o NUL -w "%{http_code}" `
        -X POST -H "Content-Type: application/json" -d "@$loginBodyPath" "$dash/api/auth/login")
    if ($loginCode -eq 200) {
        $loginOk = $true
        break
    }
    if ($loginCode -eq 429 -and $attempt -lt 5) {
        Write-Host "WAIT login rate limited (429), retry $attempt/5..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        continue
    }
    throw "Cookie login failed (HTTP $loginCode)"
}
Write-Host "OK POST /api/auth/login sets session cookie (200)"

$sessionCode = [int](& curl.exe -b $cookieJar -o NUL -w "%{http_code}" "$dash/api/auth/session")
if ($sessionCode -ne 200) { throw "Session check failed (HTTP $sessionCode)" }
Write-Host "OK GET /api/auth/session with cookie ($sessionCode)"

$overviewCode = [int](& curl.exe -b $cookieJar -o NUL -w "%{http_code}" "$dash/api/stats/overview")
if ($overviewCode -ne 200) { throw "Cookie-authenticated API failed (HTTP $overviewCode)" }
Write-Host "OK GET /api/stats/overview with cookie ($overviewCode)"

$noAuthCode = [int](& curl.exe -o NUL -w "%{http_code}" "$dash/api/stats/overview")
if ($noAuthCode -ne 401) { throw "Unauthenticated API should return 401, got $noAuthCode" }
Write-Host "OK unauthenticated API blocked ($noAuthCode)"

Write-Host "`n=== Honeypot admin gate ===" -ForegroundColor Cyan

function Test-Url {
    param([string]$Url, [int[]]$Allowed = @(200), [switch]$Dashboard)
    $args = @("-sk", "-o", "NUL", "-w", "%{http_code}")
    if ($Dashboard) { $args = $auth + $args }
    $code = [int](& curl.exe @args $Url)
    if ($code -notin $Allowed) { throw "FAIL $Url (HTTP $code)" }
    Write-Host "OK $Url ($code)"
}

Test-Url "$hp/admin" -Allowed @(302)
Test-Url "$hp/.env" -Allowed @(200, 403)
Test-Url "$hp/login" -Allowed @(200)

Write-Host "`nProduction verification passed." -ForegroundColor Green
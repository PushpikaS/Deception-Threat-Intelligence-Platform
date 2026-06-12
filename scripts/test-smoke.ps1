# Smoke test — dashboard API (cookie auth) + honeypot deception surfaces
$ErrorActionPreference = "Stop"
$dash = "http://localhost:9090"
$hp = "http://localhost:8080"
$dashUser = if ($env:DASHBOARD_AUTH_USER) { $env:DASHBOARD_AUTH_USER } else { "analyst" }
$dashPass = if ($env:DASHBOARD_AUTH_PASS) { $env:DASHBOARD_AUTH_PASS } else { "changeme_local_only" }
$cookieJar = Join-Path $env:TEMP "hp-smoke-cookies.txt"

function Test-Url {
    param(
        [string]$Url,
        [int[]]$Allowed = @(200),
        [string]$CookieJar = $null
    )
    $args = @("-o", "NUL", "-w", "%{http_code}")
    if ($CookieJar) { $args = @("-b", $CookieJar) + $args }
    $code = [int](& curl.exe @args $Url)
    if ($code -notin $Allowed) { throw "FAIL $Url (HTTP $code)" }
    Write-Host "OK $Url ($code)"
}

if (Test-Path $cookieJar) { Remove-Item $cookieJar -Force }
$loginBodyPath = Join-Path $env:TEMP "hp-smoke-login.json"
@{ username = $dashUser; password = $dashPass } | ConvertTo-Json -Compress | Set-Content -Path $loginBodyPath -Encoding UTF8 -NoNewline
$loginCode = [int](& curl.exe -c $cookieJar -o NUL -w "%{http_code}" `
    -X POST -H "Content-Type: application/json" -d "@$loginBodyPath" "$dash/api/auth/login")
if ($loginCode -ne 200) { throw "Dashboard login failed (HTTP $loginCode)" }

$apiPaths = @(
    "/api/health",
    "/api/health/platform",
    "/api/stats/overview",
    "/api/stats/trends",
    "/api/search?q=test",
    "/api/mitre/map",
    "/api/taxonomy"
)

Write-Host "=== Dashboard API ($dash) ===" -ForegroundColor Cyan
foreach ($p in $apiPaths) {
    Test-Url "$dash$p" -CookieJar $cookieJar
}

$hpPaths = @(
    "/login",
    "/jenkins",
    "/jira",
    "/storage/",
    "/upload",
    "/downloads/exports/employee-export.csv",
    "/error?code=500"
)

Write-Host "`n=== Honeypot deception ($hp) ===" -ForegroundColor Cyan
foreach ($p in $hpPaths) {
    Test-Url "$hp$p" -Allowed @(200, 202, 302, 401, 403, 500)
}

Write-Host "`nAll smoke tests passed." -ForegroundColor Green
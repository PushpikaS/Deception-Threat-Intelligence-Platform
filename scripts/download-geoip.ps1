# Download MaxMind GeoLite2 City + ASN into data/geoip/ (production-grade offline geo)
param([string]$OutputDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "data\geoip"))

$LicenseKey = $env:MAXMIND_LICENSE_KEY
if (-not $LicenseKey) {
    Write-Host "ERROR: Set MAXMIND_LICENSE_KEY environment variable" -ForegroundColor Red
    Write-Host "  1. Sign up at https://www.maxmind.com/en/geolite2/signup"
    Write-Host "  2. Create a license key in your account"
    Write-Host "  3. Run: `$env:MAXMIND_LICENSE_KEY='your_key'; .\scripts\download-geoip.ps1"
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Get-GeoDb {
    param([string]$Edition)
    $url = "https://download.maxmind.com/app/geoip_download?edition_id=$Edition&license_key=$LicenseKey&suffix=tar.gz"
    $tmp = Join-Path $env:TEMP "geoip-$Edition.tar.gz"
    Write-Host "Downloading $Edition..." -ForegroundColor Cyan
    curl.exe -fsSL -o $tmp $url
    if ($LASTEXITCODE -ne 0) { throw "Download failed for $Edition" }
    tar -xzf $tmp -C $OutputDir --strip-components=1 ("*/{0}.mmdb" -f $Edition)
    Remove-Item $tmp -Force
}

Get-GeoDb "GeoLite2-City"
Get-GeoDb "GeoLite2-ASN"

Write-Host ""
Write-Host "GeoLite2 databases saved to $OutputDir" -ForegroundColor Green
Write-Host "Restart threat-engine: docker compose restart threat-engine"
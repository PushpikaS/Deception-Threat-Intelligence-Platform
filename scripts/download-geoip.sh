#!/usr/bin/env bash
# Download MaxMind GeoLite2 databases into Docker volume
# Requires free MaxMind account: https://www.maxmind.com/en/geolite2/signup
set -euo pipefail

LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"
OUTPUT_DIR="${1:-./data/geoip}"

if [ -z "$LICENSE_KEY" ]; then
  echo "ERROR: Set MAXMIND_LICENSE_KEY environment variable"
  echo "  1. Sign up at https://www.maxmind.com/en/geolite2/signup"
  echo "  2. Generate a license key in your account"
  echo "  3. Run: MAXMIND_LICENSE_KEY=your_key ./scripts/download-geoip.sh"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

download_db() {
  local edition="$1"
  local url="https://download.maxmind.com/app/geoip_download?edition_id=${edition}&license_key=${LICENSE_KEY}&suffix=tar.gz"
  echo "Downloading $edition..."
  curl -sL "$url" | tar -xz --strip-components=1 -C "$OUTPUT_DIR" --wildcards "*/${edition}.mmdb"
}

download_db "GeoLite2-City"
download_db "GeoLite2-ASN"

echo ""
echo "Databases saved to $OUTPUT_DIR"
echo "Copy into Docker volume:"
echo "  docker compose up -d"
echo "  docker run --rm -v honeypot_geoip_data:/data/geoip -v \$(pwd)/data/geoip:/src alpine cp /src/*.mmdb /data/geoip/"
echo ""
echo "Or bind-mount ./data/geoip in docker-compose.yml instead of named volume."
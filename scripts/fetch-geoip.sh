#!/usr/bin/env bash
# Download the free DB-IP lite GeoIP databases (country + ASN) into a directory.
# No API key required (CC-BY licensed). Run monthly to refresh.
#
#   ./fetch-geoip.sh /opt/reconlens/geoip
set -euo pipefail

DEST="${1:-./geoip}"
mkdir -p "$DEST"

ym="$(date +%Y-%m)"
prev="$(date -d 'last month' +%Y-%m 2>/dev/null || echo "$ym")"

for kind in country asn; do
  ok=0
  for m in "$ym" "$prev"; do
    url="https://download.db-ip.com/free/dbip-${kind}-lite-${m}.mmdb.gz"
    if curl -fsSL "$url" -o "$DEST/dbip-${kind}.mmdb.gz"; then
      gunzip -f "$DEST/dbip-${kind}.mmdb.gz"
      echo "[geoip] fetched ${kind} database (${m})"
      ok=1
      break
    fi
  done
  [ "$ok" = 1 ] || echo "[geoip] WARN: could not download ${kind} database"
done

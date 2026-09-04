#!/usr/bin/env bash
# Sweep every root currently in scope. Targets are read live from the running
# API, so this always matches scope.yaml — add/remove targets there and the
# nightly job follows automatically.
#
# Install via cron (the Proxmox deploy script sets this up for you):
#   0 3 * * * root RECONLENS_URL=http://localhost:8077 /opt/reconlens/scripts/scheduled-scan.sh
set -euo pipefail

BASE="${RECONLENS_URL:-http://localhost:8077}"
PROFILE="${RECONLENS_PROFILE:-recon}"

targets=$(curl -fsS "$BASE/api/scope" \
  | grep -oE '"value":"[^"]+"' | sed 's/^"value":"//;s/"$//')

if [ -z "$targets" ]; then
  echo "$(date -Is) no targets in scope; nothing to scan"
  exit 0
fi

while IFS= read -r t; do
  [ -n "$t" ] || continue
  echo "$(date -Is) queuing scan: $t ($PROFILE)"
  curl -fsS -X POST "$BASE/api/scans" -H 'Content-Type: application/json' \
    -d "{\"target\":\"$t\",\"profile\":\"$PROFILE\"}" >/dev/null \
    || echo "$(date -Is) failed to queue $t"
done <<< "$targets"

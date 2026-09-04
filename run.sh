#!/usr/bin/env bash
# Compose-less runner for ReconLens.
#
# Use this if your Docker install has no `docker compose` plugin (as on the
# default WSL setup). It builds the image and runs the container with the
# right mounts + env, avoiding the single-file bind-mount footgun.
#
#   ./run.sh            # build (if needed) + run in the foreground
#   ./run.sh --rebuild  # force a rebuild first
#   ./run.sh --detach   # run in the background (see note below)
#
# NOTE on --detach under WSL: WSL2 shuts the VM down after ~60s of no attached
# session, which stops dockerd and any detached container. If you want ReconLens
# to keep running in the background, either keep a WSL terminal open, run it
# under Docker Desktop's WSL integration, or leave this script running in the
# foreground.

set -euo pipefail
cd "$(dirname "$0")"

IMAGE=reconlens:latest
NAME=reconlens
PORT=8077
DETACH=""

for arg in "$@"; do
  case "$arg" in
    --rebuild) FORCE_REBUILD=1 ;;
    --detach)  DETACH="-d" ;;
    *) echo "unknown arg: $arg"; exit 1 ;;
  esac
done

if [[ ! -f scope.yaml ]]; then
  echo "[*] No scope.yaml found — creating one from scope.example.yaml"
  cp scope.example.yaml scope.yaml
fi

# Refuse to run against the shipped placeholders (example.com is a real,
# third-party IANA domain — scanning it is not authorized).
if grep -qE '^[[:space:]]*-[[:space:]]*(example\.com|vpn\.example\.org)[[:space:]]*$' scope.yaml; then
  echo "!! scope.yaml still contains placeholder targets."
  echo "   Edit scope.yaml and list only the domain(s)/IP(s) YOU own, then re-run."
  echo "   (ReconLens will only scan what you explicitly list.)"
  exit 1
fi

mkdir -p data

if [[ "${FORCE_REBUILD:-}" == "1" ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[*] building $IMAGE ..."
  docker build -t "$IMAGE" .
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "[*] starting ReconLens on http://localhost:$PORT"
exec docker run --rm $DETACH --name "$NAME" -p "$PORT:8077" \
  -e RECONLENS_SCOPE=/app/scope.yaml \
  -e RECONLENS_DB=/app/data/reconlens.db \
  -v "$PWD/scope.yaml:/app/scope.yaml:ro" \
  -v "$PWD/data:/app/data" \
  "$IMAGE"

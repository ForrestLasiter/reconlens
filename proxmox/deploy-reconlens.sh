#!/usr/bin/env bash
# =============================================================================
# deploy-reconlens.sh — run this ON a Proxmox VE host.
#
# Creates an unprivileged Debian LXC with Docker (nesting enabled), installs
# ReconLens into it, and runs it as a systemd-managed container that survives
# reboots. Idempotent-ish: re-running updates the source and rebuilds.
#
# Usage (defaults shown):
#   CTID=110 IP=dhcp ./deploy-reconlens.sh
#   CTID=110 IP=192.168.1.50/24 GW=192.168.1.1 ./deploy-reconlens.sh
#
# Getting the code in:
#   - Public repo:  leave REPO_URL as-is (clones over HTTPS).
#   - Private repo: place a source tarball at $SRC_TARBALL on the host and it
#                   is pushed into the container instead of cloning.
# =============================================================================
set -euo pipefail

CTID="${CTID:-110}"
CT_HOSTNAME="${CT_HOSTNAME:-reconlens}"
# 24G, not 8G: compiling the five Go recon tools needs several GB of transient
# build cache on top of the image. 8G runs out of space mid-build.
DISK_GB="${DISK_GB:-24}"
RAM_MB="${RAM_MB:-2048}"
CORES="${CORES:-2}"
BRIDGE="${BRIDGE:-vmbr0}"
IP="${IP:-dhcp}"                 # or CIDR e.g. 192.168.1.50/24
GW="${GW:-}"                     # required when IP is not dhcp
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
ROOT_STORAGE="${ROOT_STORAGE:-local-lvm}"
REPO_URL="${REPO_URL:-https://github.com/ForrestLasiter/reconlens.git}"
SRC_TARBALL="${SRC_TARBALL:-/root/reconlens-src.tar.gz}"
PORT="${PORT:-8077}"
# Inbound honeypot decoy ports (comma-separated). Published from the container
# and armed as tripwires. Forward some of these on your router to catch scans.
# Set HONEYPOT_PORTS="" to disable the inbound honeypot entirely.
HONEYPOT_PORTS="${HONEYPOT_PORTS:-21,23,25,110,445,1433,3306,3389,5900,8080}"
# Offline GeoIP (free DB-IP lite) for the Threat Radar. Set GEOIP=0 to skip.
GEOIP="${GEOIP:-1}"
# Optional: ntfy topic URL for push alerts on new scanners (e.g.
# https://ntfy.sh/reconlens-<unguessable>). Empty = no alerts.
NTFY_URL="${NTFY_URL:-}"

echo "[*] ReconLens Proxmox deploy → CTID $CTID ($CT_HOSTNAME), port $PORT"

if pct status "$CTID" >/dev/null 2>&1; then
  echo "[!] CTID $CTID already exists. Reusing it (will update + rebuild)."
else
  echo "[*] Locating a Debian 12 template..."
  pveam update >/dev/null 2>&1 || true
  TEMPLATE="$(pveam list "$TEMPLATE_STORAGE" 2>/dev/null | awk '/debian-12-standard/ {print $1}' | sed 's#.*/##' | sort -V | tail -1)"
  if [ -z "${TEMPLATE:-}" ]; then
    TEMPLATE="$(pveam available --section system | awk '/debian-12-standard/ {print $2}' | sort -V | tail -1)"
    echo "[*] Downloading template $TEMPLATE ..."
    pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
  fi
  echo "[*] Using template: $TEMPLATE"

  NET="name=eth0,bridge=$BRIDGE,ip=$IP"
  if [ "$IP" != "dhcp" ]; then
    [ -n "$GW" ] || { echo "!! IP is static but GW is empty"; exit 1; }
    NET="$NET,gw=$GW"
  fi

  echo "[*] Creating unprivileged LXC (Docker-ready: nesting + keyctl)..."
  pct create "$CTID" "$TEMPLATE_STORAGE:vztmpl/$TEMPLATE" \
    --hostname "$CT_HOSTNAME" --cores "$CORES" --memory "$RAM_MB" \
    --rootfs "$ROOT_STORAGE:$DISK_GB" --net0 "$NET" \
    --features nesting=1,keyctl=1 --unprivileged 1 --onboot 1
  pct start "$CTID"
  echo "[*] Waiting for container network..."
  for _ in $(seq 1 20); do
    pct exec "$CTID" -- getent hosts deb.debian.org >/dev/null 2>&1 && break
    sleep 2
  done
fi

echo "[*] Installing Docker inside the container..."
pct exec "$CTID" -- bash -eux <<'INSIDE'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.asc ]; then
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
fi
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
INSIDE

echo "[*] Delivering ReconLens source..."
if [ -f "$SRC_TARBALL" ]; then
  echo "    using local tarball $SRC_TARBALL (private-repo mode)"
  # Extract OVER the existing tree so scope.yaml + data/ (not in the archive)
  # are preserved across updates. Refresh app/ so renamed/removed files don't
  # linger.
  pct exec "$CTID" -- mkdir -p /opt/reconlens
  pct exec "$CTID" -- rm -rf /opt/reconlens/app
  pct push "$CTID" "$SRC_TARBALL" /opt/reconlens-src.tar.gz
  pct exec "$CTID" -- tar xzf /opt/reconlens-src.tar.gz -C /opt/reconlens
  pct exec "$CTID" -- rm -f /opt/reconlens-src.tar.gz
else
  echo "    cloning $REPO_URL"
  pct exec "$CTID" -- bash -c "test -d /opt/reconlens/.git && git -C /opt/reconlens pull || git clone '$REPO_URL' /opt/reconlens"
fi

# The container runs with --network host so the honeypot sees REAL client
# source IPs (Docker's bridge NAT masks them as 172.17.0.1). With host
# networking the app binds 8077 and the decoy ports directly on the LXC.
HP_ENV=""
if [ -n "$HONEYPOT_PORTS" ]; then
  HP_ENV="-e RECONLENS_HONEYPOT_PORTS=${HONEYPOT_PORTS}"
fi
NTFY_ENV=""
if [ -n "$NTFY_URL" ]; then
  NTFY_ENV="-e RECONLENS_NTFY_URL=${NTFY_URL}"
fi

echo "[*] Building image + installing service..."
pct exec "$CTID" -- bash -eux <<INSIDE
cd /opt/reconlens
[ -f scope.yaml ] || cp scope.example.yaml scope.yaml
mkdir -p data geoip
if [ "${GEOIP}" = "1" ]; then
  bash scripts/fetch-geoip.sh /opt/reconlens/geoip || echo "geoip fetch failed (continuing without GeoIP)"
fi
docker build -t reconlens:latest .
cat > /etc/systemd/system/reconlens.service <<UNIT
[Unit]
Description=ReconLens attack-surface monitor
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/opt/reconlens
ExecStartPre=-/usr/bin/docker rm -f reconlens
ExecStart=/usr/bin/docker run --rm --name reconlens --network host \\
  -e RECONLENS_SCOPE=/app/scope.yaml -e RECONLENS_DB=/app/data/reconlens.db ${HP_ENV} ${NTFY_ENV} \\
  -e RECONLENS_GEOIP_DIR=/app/geoip \\
  -v /opt/reconlens/scope.yaml:/app/scope.yaml:ro \\
  -v /opt/reconlens/data:/app/data \\
  -v /opt/reconlens/geoip:/app/geoip:ro \\
  reconlens:latest
ExecStop=/usr/bin/docker stop reconlens
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable reconlens
INSIDE

echo "[*] Installing nightly sweep (cron)..."
pct exec "$CTID" -- bash -eux <<INSIDE
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends cron >/dev/null
systemctl enable --now cron
chmod +x /opt/reconlens/scripts/scheduled-scan.sh
cat > /etc/cron.d/reconlens-sweep <<CRON
# Nightly ReconLens sweep of everything in scope (recon profile). Edit the
# time or profile here; targets follow scope.yaml automatically.
SHELL=/bin/bash
0 3 * * * root RECONLENS_URL=http://localhost:${PORT} /opt/reconlens/scripts/scheduled-scan.sh >> /var/log/reconlens-sweep.log 2>&1
CRON
chmod 0644 /etc/cron.d/reconlens-sweep
INSIDE

CT_IP="$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')"
cat <<DONE

============================================================
 ReconLens LXC is ready (CTID $CTID).
 Container IP: ${CT_IP:-<check: pct exec $CTID -- hostname -I>}

 It is NOT scanning yet — the scope is still the placeholder.
 1. Edit the allowlist:
      pct exec $CTID -- nano /opt/reconlens/scope.yaml
 2. Start it:
      pct exec $CTID -- systemctl start reconlens
 3. Open the dashboard:
      http://${CT_IP:-<container-ip>}:${PORT}
============================================================
DONE

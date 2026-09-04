# ReconLens

![license](https://img.shields.io/badge/license-MIT-blue) ![self--hosted](https://img.shields.io/badge/self--hosted-Docker-2496ED) ![use](https://img.shields.io/badge/use-authorized%20targets%20only-critical)

A self-hosted **attack-surface monitor**. It runs authorized recon against an
allowlist of *your own* assets, stores everything in SQLite, and tracks how the
surface **drifts over time** — new subdomains, newly opened ports, new web
services, and new vulnerability findings.

It is an internet-facing defensive tool. The whole point is to see what an
outside attacker would see about *your* infrastructure, before they do. Each
person runs their **own** instance against their **own** scope — there is no
shared server and nothing phones home.

> ⚠️ **Authorized targets only.** ReconLens refuses to scan anything not listed
> in `scope.yaml`. Only add assets you own or are explicitly authorized to
> test. Port-scanning and vuln-scanning third-party systems you don't control
> can be illegal. This tool enforces the allowlist so you don't foot-gun
> yourself — don't try to work around it.

## What it runs

A pipeline of [ProjectDiscovery](https://github.com/projectdiscovery) tools,
all scope-gated at every step:

| Stage | Tool | Purpose |
|-------|------|---------|
| Subdomain enum | `subfinder` | find hostnames under your domains |
| DNS resolution | `dnsx` | resolve to IPs, drop dead names |
| Port scan | `naabu` | TCP connect scan of open ports |
| Reverse DNS | `dnsx -ptr` | name discovered hosts (for the IP Inventory) |
| Service probe | `httpx` | live web services, titles, tech, TLS, headers |
| Vuln scan | `nuclei` | CVEs, misconfigs, exposures (`full` profile) |

Results feed a dashboard with an **Overview**, a **Drift/Timeline** of what
changed, and tables for **Findings / Services / IP Inventory / Assets / Scans**.

The dashboard has two sections:

- **Attack Surface (outbound)** — the scan results above: what the internet can
  see of you.
- **Threat Radar (inbound)** — a built-in honeypot that logs who's probing you
  (see below).

## Threat Radar — the inbound honeypot

ReconLens can also watch the *other* direction: a small honeypot binds a set of
decoy ports and logs every connection attempt — **source IP, port, timestamp,
and banner** — then reverse-DNS-enriches the source (so scanners show up as
`*.censys.io`, `*.shodan.io`, etc.). Anything that connects is unsolicited by
definition: a scanner, a bot, or someone poking at you.

Enable it by setting the decoy ports (the Proxmox deploy does this for you):

```
RECONLENS_HONEYPOT_PORTS=21,23,25,110,445,1433,3306,3389,5900,8080
```

Run the container with **`--network host`** so the honeypot sees real client
IPs — Docker's bridge NAT otherwise masks every source as `172.17.0.1`. Then
**forward one or more decoy ports on your router** to the host, and internet
scans start showing up in the Threat Radar tab. It's a tripwire, not a full
packet log: it only sees the ports you point at it.

### GeoIP (offline)

Each source IP is enriched with **country + AS org**, shown as a flag in the
Threat Radar. This stays offline (no phone-home): it reads the free, no-key
**DB-IP lite** databases. Fetch them (monthly) and point ReconLens at them:

```bash
scripts/fetch-geoip.sh /opt/reconlens/geoip     # downloads country + ASN DBs
# then run the container with:
#   -v /opt/reconlens/geoip:/app/geoip:ro  -e RECONLENS_GEOIP_DIR=/app/geoip
```

No database present → GeoIP columns are simply blank; everything else works.
The Proxmox deploy fetches and mounts them automatically (set `GEOIP=0` to skip).

### Push alerts (ntfy)

Get a phone push when a **new** scanner starts probing you. Create an
unguessable [ntfy](https://ntfy.sh) topic and set:

```
RECONLENS_NTFY_URL=https://ntfy.sh/reconlens-<something-unguessable>
```

Alerts are batched into a short digest by the maintenance loop, so a scan of
many hosts sends one notification, not hundreds. Unset = no alerts. (For the
Proxmox deploy, pass `NTFY_URL=...`.)

## Quick start

ReconLens runs as a Linux container, so it works the same on **Linux, WSL, and
Windows** (Docker Desktop or WSL-backed Docker). All you need is Docker.

The runner scripts create `scope.yaml` from the example on first run and then
stop, so you can fill in your assets. You can also do it by hand:

```bash
cp scope.example.yaml scope.yaml      # then edit it — add your domain(s)/IP(s)
```

**Linux / WSL / macOS:**

```bash
./run.sh                 # build + run in the foreground
# or, if you have the compose plugin:
docker compose up --build
```

**Windows (PowerShell + Docker Desktop):**

```powershell
Copy-Item scope.example.yaml scope.yaml   # if you haven't already
.\run.ps1                # build + run in the foreground
```

Then open **http://localhost:8077**.

Both runner scripts avoid the single-file bind-mount footgun and create the
`data/` volume for you. `--rebuild` / `-Rebuild` forces a fresh image build.

**No `docker compose` plugin?** The default WSL Docker install often ships
without it. Use the bundled runner instead:

```bash
./run.sh            # build + run in the foreground
./run.sh --detach   # background (but see the WSL note below)
```

> **WSL gotcha:** WSL2 shuts its VM down after ~60s with no attached session,
> which kills a detached (`-d`) container. For a long-running background
> ReconLens under WSL, keep a terminal open, use Docker Desktop's WSL
> integration, or run `./run.sh` in the foreground. Verified working end-to-end
> on Docker 29 / Go 1.27 with a live scan of `scanme.nmap.org`.

First `nuclei` run downloads its template set into a persistent volume
(`pd_home`), so it only happens once.

Pick a target from the dropdown, choose **full** (includes nuclei) or
**recon**, and hit **▶ Scan**. Click a scan in the **Scans** tab to watch its
live log.

### Prefer not to build? Use the prebuilt image

Building compiles five Go tools (a few minutes). Once a release is published,
you can pull the image instead of building:

```bash
docker pull ghcr.io/forrestlasiter/reconlens:latest
```

Then point a container at your `scope.yaml` and a `data/` dir (see `run.sh` for
the exact flags), or set `image:` in `docker-compose.yml` to that tag.

## Running it 24/7 on a server

An attack-surface monitor is most useful when it runs continuously and scans on
a schedule. On an always-on Linux host (a VM, an LXC container, a VPS, a Pi),
run it under a process manager so it survives reboots. Example systemd unit:

```ini
# /etc/systemd/system/reconlens.service
[Unit]
Description=ReconLens attack-surface monitor
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/opt/reconlens
ExecStart=/usr/bin/docker run --rm --name reconlens -p 8077:8077 \
  -e RECONLENS_SCOPE=/app/scope.yaml -e RECONLENS_DB=/app/data/reconlens.db \
  -v /opt/reconlens/scope.yaml:/app/scope.yaml:ro \
  -v /opt/reconlens/data:/app/data \
  ghcr.io/forrestlasiter/reconlens:latest
ExecStop=/usr/bin/docker stop reconlens
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now reconlens
```

Running it on a **cloud VPS** (rather than inside your own network) gives the
truest external-attacker view of your surface. Keep the dashboard port (`8077`)
bound to localhost or behind your VPN/reverse proxy — it has no auth of its own.

### Proxmox one-shot

If you run **Proxmox VE**, [`proxmox/deploy-reconlens.sh`](proxmox/deploy-reconlens.sh)
creates a Docker-ready unprivileged LXC, installs ReconLens, and registers the
systemd service for you. Run it on the PVE host:

```bash
CTID=110 IP=192.168.1.50/24 GW=192.168.1.1 ./deploy-reconlens.sh
```

Then edit `scope.yaml` in the container and `systemctl start reconlens`.

## Configuration (`scope.yaml`)

```yaml
domains:  [ your-domain.duckdns.org ]   # subdomains enumerated under these
ips:      [ 203.0.113.10 ]              # individual owned IPs
cidrs:    [ 203.0.113.0/24 ]            # owned ranges
ports:    "top-1000"                     # or "top-100", or "80,443,8080"
min_severity: low                        # info|low|medium|high|critical
```

Changed the scope? Restart to pick it up: `docker compose restart`.

## Scheduling recurring scans

The Proxmox deploy sets up a **nightly sweep automatically** (a cron job at 3am
running [`scripts/scheduled-scan.sh`](scripts/scheduled-scan.sh), which scans
every root currently in your scope). To install it manually elsewhere:

```bash
# /etc/cron.d/reconlens-sweep
0 3 * * * root RECONLENS_URL=http://localhost:8077 /opt/reconlens/scripts/scheduled-scan.sh >> /var/log/reconlens-sweep.log 2>&1
```

Set `RECONLENS_PROFILE=full` to include nuclei on the scheduled run. Because it
reads targets from the live scope, adding a domain or CIDR to `scope.yaml` is
all it takes for the nightly job to pick it up.

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/overview` | summary counts + severity + last scan |
| GET | `/api/assets` `/services` `/findings` `/events` | current surface |
| GET | `/api/scans`, `/api/scans/{id}` | scan history + live log |
| POST | `/api/scans` `{target, profile}` | launch a scan (scope-checked) |
| GET | `/api/scope` | current allowlist + tool health |

## Pinning tool versions

The Dockerfile uses `@latest` for a first build. To pin, replace each
`go install ...@latest` with a tagged release (e.g. `@v2.6.6`) and rebuild.

## Roadmap

- Diff-based `closed_service` / `resolved_finding` events (mark surface that
  disappeared, not just what appeared)
- Deploy-on-VPS mode for a true external vantage point
- Email/ntfy alerts on new `high`/`critical` findings
- Export drift reports
- Optional dashboard authentication

## Desktop status (Conky)

ReconLens exposes a JSON API, so it drops into a status bar easily.
[`conky/reconlens.conf`](conky/reconlens.conf) +
[`scripts/conky-status.sh`](scripts/conky-status.sh) render a compact live
panel (scan stats + inbound hits) on a Linux desktop:

```bash
chmod +x scripts/conky-status.sh
conky -c conky/reconlens.conf     # edit the RECONLENS_URL + script path first
```

The same script's output is easy to reuse in any bar (polybar, waybar, tmux) —
it just prints a few lines from `/api/overview` and `/api/inbound/summary`.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The one hard
rule: **never weaken the scope gate.** The allowlist is what keeps ReconLens a
defensive tool.

## Security & responsible use

ReconLens performs active reconnaissance. Use it **only** against systems you
own or are explicitly authorized to test — see [SECURITY.md](SECURITY.md) for
the details and how to report a vulnerability in ReconLens itself.

## License

[MIT](LICENSE) © 2026 Forrest Lasiter. Provided "as is", without warranty; you
are responsible for using it lawfully and only within your authorized scope.

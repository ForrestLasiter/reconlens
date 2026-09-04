# Contributing to ReconLens

Thanks for your interest! ReconLens is a small, self-hosted attack-surface
monitor. Contributions that keep it simple, safe, and easy to self-host are
very welcome.

## Ground rules

- **Never weaken the scope gate.** The allowlist in `app/scope.py` is the core
  safety guarantee. Changes that let ReconLens touch out-of-scope hosts will not
  be merged. New scan stages must filter their inputs through the scope before
  sending traffic.
- Keep the dependency footprint small. The backend is deliberately plain
  FastAPI + SQLite + the ProjectDiscovery CLIs; the frontend is dependency-free
  vanilla JS.
- No telemetry, no phone-home. Everything stays on the operator's host.

## Dev setup

Everything runs in the container, so you don't need the Go tools locally.

```bash
git clone https://github.com/ForrestLasiter/reconlens
cd reconlens
cp scope.example.yaml scope.yaml     # add a domain YOU own for testing
./run.sh                             # build + run on http://localhost:8077
```

`scanme.nmap.org` is published by the Nmap project expressly for testing
scanners, and is a safe target to put in `scope.yaml` while developing.

### Iterating on the frontend

The dashboard is static (`app/static/`). You can bind-mount it over the image
to skip rebuilds while editing:

```bash
docker run --rm -p 8077:8077 \
  -e RECONLENS_SCOPE=/app/scope.yaml -e RECONLENS_DB=/app/data/reconlens.db \
  -v "$PWD/scope.yaml:/app/scope.yaml:ro" -v "$PWD/data:/app/data" \
  -v "$PWD/app:/app/app" reconlens:latest
```

## Project layout

| Path | Purpose |
|------|---------|
| `app/scope.py`   | Allowlist loading + enforcement (the safety core) |
| `app/tools.py`   | Wrappers around subfinder/dnsx/naabu/httpx/nuclei |
| `app/scanner.py` | Pipeline orchestration + drift/event computation |
| `app/db.py`      | SQLite schema + helpers |
| `app/main.py`    | FastAPI routes + static serving |
| `app/static/`    | Dashboard (vanilla JS/CSS) |

## Pull requests

1. Fork and branch from `main`.
2. Keep changes focused; describe what and why.
3. If you add a scan stage or data type, update the README pipeline table.
4. Confirm a full scan of a domain you own still completes cleanly.

## Ideas / roadmap

See the **Roadmap** section in the README. Good first issues: closed-service /
resolved-finding drift events, ntfy/email alerting, and a "top-ports" preset
picker in the UI.

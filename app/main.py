"""ReconLens API + dashboard.

A self-hosted attack-surface monitor. Runs authorized recon against an
allowlist of your own assets and tracks how the surface drifts over time.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import alerts, geoip, honeypot, scanner, tools
from .db import db, init_db, now
from .scope import load_scope

app = FastAPI(title="ReconLens", version="1.0.0")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.on_event("startup")
async def _startup() -> None:
    init_db()
    ports = honeypot.configured_ports()
    if ports:
        app.state.honeypot = await honeypot.start(ports)
    app.state.alert_after = now()  # only alert on scanners seen after startup
    asyncio.create_task(_maintenance_loop())


async def _maintenance_loop() -> None:
    """Enrich inbound source IPs (reverse-DNS + offline GeoIP) and push a
    digest alert for any new scanners since the last pass."""
    while True:
        await asyncio.sleep(45)
        try:
            await asyncio.to_thread(_enrich_sources)
            await asyncio.to_thread(_alert_new_sources)
        except Exception:
            pass


def _enrich_sources() -> None:
    ips = [r["src_ip"] for r in _rows(
        "SELECT DISTINCT src_ip FROM inbound_events WHERE hostname IS NULL "
        "LIMIT 50")]
    for ip in ips:
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        geo = geoip.lookup(ip)
        with db() as conn:
            conn.execute(
                "UPDATE inbound_events SET hostname=?, country=?, "
                "country_code=?, org=? WHERE src_ip=? AND hostname IS NULL",
                (name, geo["country"], geo["country_code"], geo["org"], ip))


def _alert_new_sources() -> None:
    if not alerts.enabled():
        return
    after = getattr(app.state, "alert_after", 0)
    rows = _rows(
        "SELECT src_ip, MAX(hostname) hostname, MAX(country) country, "
        "MIN(dst_port) port, MIN(ts) first_seen FROM inbound_events "
        "GROUP BY src_ip HAVING first_seen > ? ORDER BY first_seen", (after,))
    if not rows:
        return
    alerts.notify_new_sources(rows)
    app.state.alert_after = max(r["first_seen"] for r in rows)


def _rows(sql: str, params: tuple = ()) -> list[dict]:
    with db() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


@app.get("/api/scope")
def get_scope():
    s = load_scope()
    return {
        "domains": s.domains,
        "ips": s.ips,
        "cidrs": s.cidrs,
        "ports": s.ports,
        "min_severity": s.min_severity,
        "targets": s.targets(),
        "missing_tools": tools.missing_tools(),
    }


@app.get("/api/overview")
def overview():
    with db() as conn:
        def scalar(sql, p=()):
            return conn.execute(sql, p).fetchone()[0]

        sev_counts = {r["severity"]: r["n"] for r in conn.execute(
            "SELECT severity, COUNT(*) n FROM findings WHERE status='open' "
            "GROUP BY severity"
        ).fetchall()}

        return {
            "assets": scalar("SELECT COUNT(*) FROM assets"),
            "alive": scalar("SELECT COUNT(*) FROM assets WHERE alive=1"),
            "services": scalar("SELECT COUNT(*) FROM services WHERE open=1"),
            "findings_open": scalar(
                "SELECT COUNT(*) FROM findings WHERE status='open'"),
            "severity": {
                s: sev_counts.get(s, 0)
                for s in ["critical", "high", "medium", "low", "info"]
            },
            "last_scan": (lambda r: dict(r) if r else None)(conn.execute(
                "SELECT id, target, status, started_at, finished_at "
                "FROM scans ORDER BY id DESC LIMIT 1").fetchone()),
        }


@app.get("/api/assets")
def assets():
    return _rows("SELECT * FROM assets ORDER BY last_seen DESC")


@app.get("/api/services")
def services():
    return _rows("SELECT * FROM services WHERE open=1 ORDER BY host, port")


@app.get("/api/inbound/summary")
def inbound_summary():
    with db() as conn:
        def scalar(sql):
            return conn.execute(sql).fetchone()[0]
        return {
            "enabled": bool(honeypot.configured_ports()),
            "watched_ports": honeypot.configured_ports(),
            "geoip": geoip.available(),
            "alerts": alerts.enabled(),
            "total": scalar("SELECT COUNT(*) FROM inbound_events"),
            "unique_sources": scalar(
                "SELECT COUNT(DISTINCT src_ip) FROM inbound_events"),
            "last_hit": scalar("SELECT MAX(ts) FROM inbound_events"),
            "top_ports": [dict(r) for r in conn.execute(
                "SELECT dst_port, COUNT(*) n FROM inbound_events "
                "GROUP BY dst_port ORDER BY n DESC LIMIT 12")],
            "top_sources": [dict(r) for r in conn.execute(
                "SELECT src_ip, MAX(hostname) hostname, MAX(country) country, "
                "MAX(country_code) country_code, MAX(org) org, COUNT(*) n, "
                "COUNT(DISTINCT dst_port) ports, MAX(ts) last "
                "FROM inbound_events GROUP BY src_ip ORDER BY n DESC LIMIT 25")],
        }


@app.get("/api/inbound")
def inbound(limit: int = 200):
    return _rows("SELECT ts, src_ip, src_port, dst_port, hostname, banner, "
                 "country, country_code, org "
                 "FROM inbound_events ORDER BY id DESC LIMIT ?", (limit,))


@app.get("/api/inventory")
def inventory():
    """Host-centric IP inventory: every host with its open ports."""
    rows = _rows("SELECT host, ip, hostname, port, last_seen FROM ports "
                 "WHERE open=1 ORDER BY host, port")
    inv: dict[str, dict] = {}
    for r in rows:
        h = r["host"]
        if h not in inv:
            inv[h] = {"host": h, "ip": r["ip"], "hostname": r["hostname"] or "",
                      "ports": [], "last_seen": r["last_seen"]}
        inv[h]["ports"].append(r["port"])
        if r["hostname"] and not inv[h]["hostname"]:
            inv[h]["hostname"] = r["hostname"]
        inv[h]["last_seen"] = max(inv[h]["last_seen"] or 0, r["last_seen"] or 0)
    # Sort by dotted-quad numerically when possible, else lexically.
    def _key(d):
        parts = (d["ip"] or d["host"]).split(".")
        try:
            return (0, tuple(int(x) for x in parts))
        except ValueError:
            return (1, d["host"])
    return sorted(inv.values(), key=_key)


@app.get("/api/findings")
def findings():
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
             "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END")
    return _rows(
        f"SELECT * FROM findings WHERE status='open' "
        f"ORDER BY {order}, last_seen DESC")


@app.get("/api/events")
def events(limit: int = 100):
    return _rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))


@app.get("/api/scans")
def scans():
    return _rows("SELECT id, target, profile, status, started_at, "
                 "finished_at, stats FROM scans ORDER BY id DESC LIMIT 50")


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int):
    rows = _rows("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not rows:
        raise HTTPException(404, "scan not found")
    return rows[0]


class ScanRequest(BaseModel):
    target: str
    profile: str = "full"


@app.post("/api/scans")
def start_scan(req: ScanRequest):
    scope = load_scope()
    if not scope.is_root_target(req.target):
        raise HTTPException(
            400,
            f"'{req.target}' is not in scope.yaml. Add it to the allowlist "
            f"first — ReconLens only scans assets you list.",
        )
    if req.profile not in ("full", "recon"):
        raise HTTPException(400, "profile must be 'full' or 'recon'")
    scan_id = scanner.enqueue_scan(req.target, req.profile)
    return {"scan_id": scan_id, "status": "queued"}


# ---- Static dashboard ----
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

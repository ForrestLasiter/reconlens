"""Scan orchestration: run the pipeline, persist results, compute drift.

A single background worker processes one scan at a time so the tools never
stampede the target. Everything is scope-gated: any host that isn't in the
allowlist is dropped before a packet is sent.
"""
from __future__ import annotations

import ipaddress
import json
import threading
from concurrent.futures import ThreadPoolExecutor

from . import tools
from .db import db, now
from .scope import load_scope

# Single-worker queue: one scan at a time.
_executor = ThreadPoolExecutor(max_workers=1)
_lock = threading.Lock()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _target_kind(target: str) -> str:
    """Classify a scope root as 'domain', 'ip', or 'cidr'."""
    if "/" in target:
        return "cidr"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def enqueue_scan(target: str, profile: str = "full") -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, profile, status, started_at) "
            "VALUES (?, ?, 'queued', ?)",
            (target, profile, now()),
        )
        scan_id = cur.lastrowid
    _executor.submit(_run_scan, scan_id, target, profile)
    return scan_id


def _log(scan_id: int, msg: str) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE scans SET log = log || ? WHERE id = ?",
            (msg + "\n", scan_id),
        )


def _set_status(scan_id: int, status: str, **fields) -> None:
    sets = ["status = ?"]
    vals: list = [status]
    for k, v in fields.items():
        sets.append(f"{k} = ?")
        vals.append(v)
    vals.append(scan_id)
    with db() as conn:
        conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)


def _event(conn, kind: str, subject: str, detail: str,
           severity: str, scan_id: int) -> None:
    conn.execute(
        "INSERT INTO events (ts, kind, severity, subject, detail, scan_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (now(), kind, severity, subject, detail, scan_id),
    )


def _run_scan(scan_id: int, target: str, profile: str) -> None:
    with _lock:
        try:
            _do_run_scan(scan_id, target, profile)
        except Exception as exc:  # noqa: BLE001
            _log(scan_id, f"[!] FATAL: {exc}")
            _set_status(scan_id, "error", finished_at=now(), error=str(exc))


def _do_run_scan(scan_id: int, target: str, profile: str) -> None:
    scope = load_scope()
    _set_status(scan_id, "running")
    _log(scan_id, f"[*] Scan starting for {target} (profile={profile})")

    missing = tools.missing_tools()
    if missing:
        raise RuntimeError(f"missing recon tools in image: {', '.join(missing)}")

    # Safety gate: never scan a root that isn't explicitly in scope.
    if not scope.is_root_target(target):
        raise RuntimeError(f"target {target!r} is not a root entry in scope.yaml")

    ts = now()
    stats = {"subdomains": 0, "resolved": 0, "ports": 0, "services": 0,
             "findings": 0}
    kind = _target_kind(target)
    host_ip: dict[str, str] = {}

    if kind == "domain":
        # 1. Subdomain enumeration.
        _log(scan_id, "[*] subfinder: enumerating subdomains...")
        subs = tools.subfinder(target)
        hosts = set(subs) | {target}
        _log(scan_id, f"    found {len(subs)} subdomains")

        # Scope filter (subfinder can return out-of-scope CNAMEs).
        hosts = set(scope.filter_in_scope(list(hosts))) or {target}
        stats["subdomains"] = len(hosts)

        # 2. DNS resolution.
        _log(scan_id, "[*] dnsx: resolving...")
        for r in tools.dnsx(sorted(hosts)):
            if r["a"]:
                host_ip[r["host"]] = r["a"][0]
        stats["resolved"] = len(host_ip)
        _log(scan_id, f"    {len(host_ip)} hosts resolved")
        live_hosts = [h for h in host_ip if scope.in_scope(h)]

    elif kind == "ip":
        # Single IP: no enumeration/resolution needed.
        host_ip[target] = target
        stats["subdomains"] = stats["resolved"] = 1
        live_hosts = [target]

    else:  # cidr
        # Feed the range straight to the port scanner; naabu expands it.
        _log(scan_id, f"[*] target is a CIDR range ({target})")
        live_hosts = [target]

    # 3. Port scan (connect scan) against in-scope targets.
    _log(scan_id, f"[*] naabu: port scan on {len(live_hosts)} hosts...")
    ports = tools.naabu(live_hosts, scope.ports) if live_hosts else []
    stats["ports"] = len(ports)
    _log(scan_id, f"    {len(ports)} open ports")

    # 3b. Reverse-DNS so the inventory shows device names, not just IPs.
    ptr: dict[str, str] = {}
    scan_ips = sorted({p.get("ip") or p["host"] for p in ports})
    scan_ips = [x for x in scan_ips if _is_ip(x)]
    if scan_ips:
        _log(scan_id, f"[*] dnsx: reverse-DNS on {len(scan_ips)} hosts...")
        ptr = tools.dnsx_ptr(scan_ips)
        _log(scan_id, f"    {len(ptr)} names resolved")

    # 4. httpx probe on discovered host:port pairs (+ bare hosts as fallback).
    probe_targets = [f"{p['host']}:{p['port']}" for p in ports]
    if not probe_targets:
        probe_targets = live_hosts
    _log(scan_id, f"[*] httpx: probing {len(probe_targets)} endpoints...")
    web = tools.httpx(probe_targets)
    web = [w for w in web if scope.in_scope(w["host"])]
    stats["services"] = len(web)
    _log(scan_id, f"    {len(web)} live web services")

    # 5. nuclei against live URLs.
    urls = [w["url"] for w in web if w.get("url")]
    findings = []
    if profile == "full" and urls:
        _log(scan_id, "[*] nuclei: updating templates...")
        tools.update_nuclei_templates()
        _log(scan_id, f"[*] nuclei: scanning {len(urls)} URLs "
                      f"(min severity: {scope.min_severity})...")
        findings = tools.nuclei(urls, scope.min_severity)
        findings = [f for f in findings if scope.in_scope(f["host"])]
    stats["findings"] = len(findings)
    _log(scan_id, f"    {len(findings)} findings")

    # ---- Persist + drift ----
    _persist(scan_id, host_ip, ports, ptr, web, findings, ts)

    _set_status(scan_id, "done", finished_at=now(),
                stats=json.dumps(stats))
    _log(scan_id, "[*] Scan complete.")


def _persist(scan_id, host_ip, ports, ptr, web, findings, ts) -> None:
    with db() as conn:
        # Assets
        for host, ip in host_ip.items():
            row = conn.execute(
                "SELECT hostname FROM assets WHERE hostname = ?", (host,)
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO assets (hostname, ip, source, first_seen, "
                    "last_seen, alive) VALUES (?, ?, 'dns', ?, ?, 1)",
                    (host, ip, ts, ts),
                )
                _event(conn, "new_asset", host, f"resolves to {ip}",
                       "info", scan_id)
            else:
                conn.execute(
                    "UPDATE assets SET ip = ?, last_seen = ?, alive = 1 "
                    "WHERE hostname = ?", (ip, ts, host),
                )

        # Open ports (from naabu) -> IP Inventory. First host seen on a
        # sweep counts as a discovered host; each port is tracked for drift.
        seen_hosts = set()
        for p in ports:
            host, ip, port = p["host"], p.get("ip", ""), p["port"]
            name = ptr.get(ip) or ptr.get(host) or ""
            label = name or ip or host
            if host not in seen_hosts:
                seen_hosts.add(host)
                exists = conn.execute(
                    "SELECT 1 FROM ports WHERE host = ? LIMIT 1", (host,)
                ).fetchone()
                if exists is None:
                    _event(conn, "new_host", label,
                           f"host up ({ip or host})", "info", scan_id)
            row = conn.execute(
                "SELECT id FROM ports WHERE host = ? AND port = ?",
                (host, port),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO ports (host, ip, hostname, port, first_seen, "
                    "last_seen, open) VALUES (?,?,?,?,?,?,1)",
                    (host, ip, name, port, ts, ts),
                )
                _event(conn, "new_port", f"{label}:{port}",
                       "port opened", "low", scan_id)
            else:
                conn.execute(
                    "UPDATE ports SET ip=?, hostname=?, last_seen=?, open=1 "
                    "WHERE id=?", (ip, name, ts, row["id"]),
                )

        # Services (from httpx)
        seen_services = set()
        for w in web:
            host = w["host"]
            port = w.get("port") or (443 if w["scheme"] == "https" else 80)
            seen_services.add((host, port))
            tech = ",".join(w.get("tech", []))
            row = conn.execute(
                "SELECT id FROM services WHERE host = ? AND port = ?",
                (host, port),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO services (host, port, scheme, url, "
                    "status_code, title, webserver, tech, tls_host, "
                    "tls_expiry, first_seen, last_seen, open) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)",
                    (host, port, w["scheme"], w["url"], w["status_code"],
                     w["title"], w["webserver"], tech, w["tls_host"],
                     w["tls_expiry"], ts, ts),
                )
                _event(conn, "new_service", f"{host}:{port}",
                       f"{w['scheme']} {w.get('status_code','')} "
                       f"{w.get('title','')}".strip(), "low", scan_id)
            else:
                conn.execute(
                    "UPDATE services SET scheme=?, url=?, status_code=?, "
                    "title=?, webserver=?, tech=?, tls_host=?, tls_expiry=?, "
                    "last_seen=?, open=1 WHERE host=? AND port=?",
                    (w["scheme"], w["url"], w["status_code"], w["title"],
                     w["webserver"], tech, w["tls_host"], w["tls_expiry"],
                     ts, host, port),
                )

        # Findings (from nuclei)
        for f in findings:
            row = conn.execute(
                "SELECT id FROM findings WHERE host=? AND template_id=? "
                "AND matched_at=?",
                (f["host"], f["template_id"], f["matched_at"]),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO findings (host, template_id, name, severity, "
                    "matched_at, first_seen, last_seen, status) "
                    "VALUES (?,?,?,?,?,?,?, 'open')",
                    (f["host"], f["template_id"], f["name"], f["severity"],
                     f["matched_at"], ts, ts),
                )
                _event(conn, "new_finding",
                       f"{f['name'] or f['template_id']}",
                       f"{f['severity'].upper()} @ {f['matched_at']}",
                       f["severity"], scan_id)
            else:
                conn.execute(
                    "UPDATE findings SET last_seen=?, status='open' WHERE id=?",
                    (ts, row["id"]),
                )

"""Thin wrappers around the ProjectDiscovery recon binaries.

Each function shells out, parses newline-delimited JSON, and returns plain
Python structures. All are tolerant of empty output and non-zero exits (these
tools often exit non-zero when they simply find nothing).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Iterable


def _run(cmd: list[str], stdin_lines: Iterable[str] | None = None,
         timeout: int = 900) -> str:
    stdin_data = None
    if stdin_lines is not None:
        stdin_data = "\n".join(stdin_lines) + "\n"
    proc = subprocess.run(
        cmd,
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.stdout


def _jsonl(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def missing_tools() -> list[str]:
    return [t for t in ("subfinder", "dnsx", "naabu", "httpx", "nuclei")
            if not tool_available(t)]


def subfinder(domain: str) -> list[str]:
    """Enumerate subdomains of a root domain."""
    out = _run(["subfinder", "-d", domain, "-silent", "-all"], timeout=600)
    return sorted({l.strip().lower() for l in out.splitlines() if l.strip()})


def dnsx(hosts: list[str]) -> list[dict]:
    """Resolve hosts to A records. Returns [{host, a: [ips]}]."""
    if not hosts:
        return []
    text = _run(["dnsx", "-silent", "-json", "-a", "-resp"],
                stdin_lines=hosts, timeout=300)
    rows = []
    for rec in _jsonl(text):
        rows.append({
            "host": rec.get("host", "").lower(),
            "a": rec.get("a", []) or [],
        })
    return rows


def _system_resolvers() -> list[str]:
    """Nameservers from /etc/resolv.conf — the LAN's own DNS, which knows
    local device names (via DHCP), unlike dnsx's default public resolvers."""
    out = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    out.append(parts[1])
    except OSError:
        pass
    return out


def dnsx_ptr(ips: list[str]) -> dict[str, str]:
    """Reverse-DNS (PTR) lookup. Returns {ip: hostname} for those that resolve.

    Uses the system resolver (the LAN's DNS / router), which serves PTR for
    local subnets; dnsx's default public resolvers never would. Hosts with no
    reverse record are simply left blank.
    """
    if not ips:
        return {}
    cmd = ["dnsx", "-silent", "-json", "-ptr"]
    resolvers = _system_resolvers()
    if resolvers:
        cmd += ["-r", ",".join(resolvers)]
    text = _run(cmd, stdin_lines=ips, timeout=180)
    out: dict[str, str] = {}
    for rec in _jsonl(text):
        ip = rec.get("host", "")
        ptr = rec.get("ptr", []) or []
        if ip and ptr:
            out[ip] = ptr[0].rstrip(".")
    return out


def naabu(hosts: list[str], ports: str = "top-1000") -> list[dict]:
    """TCP connect port scan. Returns [{host, port}]."""
    if not hosts:
        return []
    cmd = ["naabu", "-silent", "-json", "-scan-type", "c", "-no-color"]
    if ports and ports.startswith("top-"):
        cmd += ["-top-ports", ports.split("-", 1)[1]]
    elif ports:
        cmd += ["-p", ports]
    text = _run(cmd, stdin_lines=hosts, timeout=900)
    rows = []
    for rec in _jsonl(text):
        ip = rec.get("ip", "")
        host = rec.get("host") or ip
        port = rec.get("port")
        if host and port:
            rows.append({"host": str(host).lower(), "ip": ip, "port": int(port)})
    return rows


def httpx(targets: list[str]) -> list[dict]:
    """Probe web services. `targets` may be host:port or bare hosts."""
    if not targets:
        return []
    cmd = [
        "httpx", "-silent", "-json", "-no-color",
        "-status-code", "-title", "-tech-detect", "-web-server",
        "-tls-grab", "-follow-redirects",
    ]
    text = _run(cmd, stdin_lines=targets, timeout=600)
    rows = []
    for rec in _jsonl(text):
        tls = rec.get("tls") or {}
        rows.append({
            "url": rec.get("url", ""),
            "host": (rec.get("host") or rec.get("input") or "").lower(),
            "port": int(rec.get("port")) if rec.get("port") else None,
            "scheme": rec.get("scheme", ""),
            "status_code": rec.get("status_code"),
            "title": rec.get("title", ""),
            "webserver": rec.get("webserver", ""),
            "tech": rec.get("tech", []) or [],
            "tls_host": tls.get("host", "") or tls.get("subject_cn", ""),
            "tls_expiry": tls.get("not_after", ""),
        })
    return rows


def nuclei(urls: list[str], min_severity: str = "low") -> list[dict]:
    """Run nuclei templates against live URLs."""
    if not urls:
        return []
    sev_order = ["info", "low", "medium", "high", "critical"]
    idx = sev_order.index(min_severity) if min_severity in sev_order else 1
    severities = ",".join(sev_order[idx:])
    cmd = [
        "nuclei", "-silent", "-jsonl", "-no-color",
        "-severity", severities,
        "-rate-limit", "50",
        "-timeout", "10",
    ]
    text = _run(cmd, stdin_lines=urls, timeout=1800)
    rows = []
    for rec in _jsonl(text):
        info = rec.get("info", {}) or {}
        rows.append({
            "host": (rec.get("host") or rec.get("matched-at") or "").lower(),
            "template_id": rec.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": (info.get("severity") or "info").lower(),
            "matched_at": rec.get("matched-at", ""),
        })
    return rows


def update_nuclei_templates() -> None:
    """Best-effort template refresh; ignored if it fails (offline, etc.)."""
    try:
        subprocess.run(["nuclei", "-update-templates", "-silent"],
                       capture_output=True, text=True, timeout=600)
    except Exception:
        pass

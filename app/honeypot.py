"""A minimal TCP honeypot — the inbound half of ReconLens.

It binds a set of decoy ports and logs every connection attempt (source IP,
port, timestamp, and whatever the client sends first). It is a *tripwire*, not
a service: it records the hit and closes. Anything that connects to a decoy
port is, by definition, unsolicited — a scanner, a bot, or someone poking at
your surface.

Enable by setting RECONLENS_HONEYPOT_PORTS to a comma-separated port list and
publishing those ports from the container. The listeners run inside the same
event loop as the API.
"""
from __future__ import annotations

import asyncio
import os

from .db import db, now

# Sensible decoy defaults: classic attacker-scanned ports that are NOT real
# services. Override with RECONLENS_HONEYPOT_PORTS.
DEFAULT_PORTS = "21,23,25,110,445,1433,3306,3389,5900,8080"


def configured_ports() -> list[int]:
    raw = os.environ.get("RECONLENS_HONEYPOT_PORTS", "")
    ports: list[int] = []
    for tok in raw.split(","):
        tok = tok.strip()
        if tok.isdigit():
            p = int(tok)
            if 0 < p < 65536 and p not in ports:
                ports.append(p)
    return ports


def _log_hit(src_ip: str, src_port: int, dst_port: int, banner: bytes) -> None:
    text = banner.decode("latin-1", "replace")[:200] if banner else ""
    with db() as conn:
        conn.execute(
            "INSERT INTO inbound_events (ts, src_ip, src_port, dst_port, banner)"
            " VALUES (?,?,?,?,?)",
            (now(), src_ip, src_port, dst_port, text),
        )


async def _handle(reader, writer, dst_port: int) -> None:
    peer = writer.get_extra_info("peername") or ("", 0)
    src_ip, src_port = (peer[0], peer[1]) if len(peer) >= 2 else ("", 0)
    banner = b""
    try:
        banner = await asyncio.wait_for(reader.read(256), timeout=2.0)
    except Exception:
        pass
    try:
        writer.close()
    except Exception:
        pass
    # Keep the DB write off the event loop.
    try:
        await asyncio.to_thread(_log_hit, src_ip, src_port, dst_port, banner)
    except Exception:
        pass


async def start(ports: list[int]) -> list:
    """Start a listener per port. Returns the started servers (ports that were
    unavailable are skipped)."""
    servers = []
    for p in ports:
        try:
            srv = await asyncio.start_server(
                lambda r, w, port=p: _handle(r, w, port), "0.0.0.0", p)
            servers.append(srv)
        except OSError:
            continue
    return servers

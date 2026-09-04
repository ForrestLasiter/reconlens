"""Push alerts for new inbound scanners, via ntfy.

Set RECONLENS_NTFY_URL to a full ntfy topic URL (e.g.
https://ntfy.sh/reconlens-<something-unguessable>) to get a phone push when a
new source IP starts probing you. Unset = no alerts. Alerts are sent as a
short digest (batched by the maintenance loop) so a port scan of many hosts
doesn't flood you.
"""
from __future__ import annotations

import os
import urllib.request


def enabled() -> bool:
    return bool(os.environ.get("RECONLENS_NTFY_URL"))


def send(title: str, body: str, tags: str = "warning") -> None:
    url = os.environ.get("RECONLENS_NTFY_URL")
    if not url:
        return
    try:
        req = urllib.request.Request(
            url, data=body.encode("utf-8"),
            headers={"Title": title, "Tags": tags, "Priority": "default"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=6)
    except Exception:
        pass


def notify_new_sources(sources: list[dict]) -> None:
    """`sources` = [{src_ip, hostname, country, ports}]."""
    if not sources or not enabled():
        return
    n = len(sources)
    title = f"ReconLens: {n} new scanner{'s' if n != 1 else ''}"
    lines = []
    for s in sources[:10]:
        who = s.get("hostname") or s.get("src_ip")
        loc = f" [{s['country']}]" if s.get("country") else ""
        lines.append(f"{who}{loc} → port {s.get('port', '?')}")
    if n > 10:
        lines.append(f"…and {n - 10} more")
    send(title, "\n".join(lines))

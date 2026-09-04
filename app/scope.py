"""Scope allowlist — the safety boundary for ReconLens.

Every target and every discovered host is validated against this before any
tool is allowed to touch it. If it isn't in scope, it doesn't get scanned.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

import yaml

SCOPE_PATH = os.environ.get("RECONLENS_SCOPE", "scope.yaml")

VALID_SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Scope:
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    ports: str = "top-1000"
    min_severity: str = "low"

    @property
    def _networks(self) -> list[ipaddress._BaseNetwork]:
        nets: list[ipaddress._BaseNetwork] = []
        for ip in self.ips:
            try:
                nets.append(ipaddress.ip_network(ip.strip(), strict=False))
            except ValueError:
                continue
        for cidr in self.cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
            except ValueError:
                continue
        return nets

    def targets(self) -> list[dict]:
        """Scannable roots the user can launch a scan against."""
        out = [{"value": d, "kind": "domain"} for d in self.domains]
        out += [{"value": ip, "kind": "ip"} for ip in self.ips]
        out += [{"value": c, "kind": "cidr"} for c in self.cidrs]
        return out

    def is_root_target(self, target: str) -> bool:
        """Is `target` a top-level entry the user may launch a scan on?"""
        target = target.strip().lower()
        return (
            target in [d.lower() for d in self.domains]
            or target in [i.lower() for i in self.ips]
            or target in [c.lower() for c in self.cidrs]
        )

    def in_scope(self, host: str) -> bool:
        """Is a discovered host/IP allowed to be probed?"""
        host = host.strip().lower().rstrip(".")
        if not host:
            return False

        # IP check
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in self._networks)
        except ValueError:
            pass

        # Domain / subdomain check
        for d in self.domains:
            d = d.lower().strip()
            if host == d or host.endswith("." + d):
                return True
        return False

    def filter_in_scope(self, hosts: list[str]) -> list[str]:
        return [h for h in hosts if self.in_scope(h)]


def load_scope(path: str | None = None) -> Scope:
    path = path or SCOPE_PATH
    if not os.path.exists(path):
        # Empty scope: nothing is scannable until the user fills scope.yaml.
        return Scope()
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    sev = str(raw.get("min_severity", "low")).lower().strip()
    if sev not in VALID_SEVERITIES:
        sev = "low"

    return Scope(
        domains=[str(x).strip() for x in (raw.get("domains") or []) if x],
        ips=[str(x).strip() for x in (raw.get("ips") or []) if x],
        cidrs=[str(x).strip() for x in (raw.get("cidrs") or []) if x],
        ports=str(raw.get("ports", "top-1000")).strip() or "top-1000",
        min_severity=sev,
    )

"""Offline GeoIP lookup for inbound source IPs.

Keeps ReconLens's "nothing phones home" promise: it reads local MaxMind-format
`.mmdb` databases (e.g. the free, no-key DB-IP lite country + ASN databases)
from RECONLENS_GEOIP_DIR. If no database is present, lookups return blanks and
everything else still works.

    scripts/fetch-geoip.sh downloads the current DB-IP lite databases.
"""
from __future__ import annotations

import glob
import os

try:
    import maxminddb
except Exception:  # pragma: no cover
    maxminddb = None

_readers: dict | None = None


def _load() -> dict:
    global _readers
    if _readers is not None:
        return _readers
    _readers = {}
    d = os.environ.get("RECONLENS_GEOIP_DIR", "/app/geoip")
    if not maxminddb or not os.path.isdir(d):
        return _readers
    for path in glob.glob(os.path.join(d, "*.mmdb")):
        name = os.path.basename(path).lower()
        try:
            reader = maxminddb.open_database(path)
        except Exception:
            continue
        if "asn" in name:
            _readers["asn"] = reader
        elif "country" in name or "city" in name:
            _readers["geo"] = reader
    return _readers


def available() -> bool:
    return bool(_load())


def lookup(ip: str) -> dict:
    """Best-effort {country, country_code, org}. Blanks when no DB / no match."""
    out = {"country": "", "country_code": "", "org": ""}
    rd = _load()
    try:
        geo = rd.get("geo")
        if geo:
            rec = geo.get(ip) or {}
            country = rec.get("country") or rec.get("registered_country") or {}
            out["country"] = (country.get("names") or {}).get("en", "")
            out["country_code"] = country.get("iso_code", "")
    except Exception:
        pass
    try:
        asn = rd.get("asn")
        if asn:
            rec = asn.get(ip) or {}
            out["org"] = (rec.get("autonomous_system_organization")
                          or rec.get("as_org") or "")
    except Exception:
        pass
    return out

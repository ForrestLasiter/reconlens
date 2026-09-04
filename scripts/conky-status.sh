#!/usr/bin/env bash
# Compact ReconLens status for Conky (or any status bar).
# Use from conky with:  ${execi 30 /opt/reconlens/scripts/conky-status.sh}
# Point it at your instance with RECONLENS_URL (default below).
BASE="${RECONLENS_URL:-http://localhost:8077}"

ov=$(curl -fsS --max-time 4 "$BASE/api/overview" 2>/dev/null) || {
  echo "ReconLens: offline"; exit 0;
}
ib=$(curl -fsS --max-time 4 "$BASE/api/inbound/summary" 2>/dev/null || echo '{}')

python3 - "$ov" "$ib" <<'PY'
import sys, json, time
ov = json.loads(sys.argv[1] or "{}")
ib = json.loads(sys.argv[2] or "{}")

def ago(ts):
    if not ts:
        return "never"
    s = max(0, time.time() - ts)
    for d, u in ((86400, "d"), (3600, "h"), (60, "m"), (1, "s")):
        if s >= d:
            return f"{int(s // d)}{u} ago"
    return "now"

sev = ov.get("severity", {}) or {}
last = ov.get("last_scan") or {}
print(f"Assets {ov.get('assets',0)}  Live {ov.get('alive',0)}  Svc {ov.get('services',0)}")
print(f"Vulns  C:{sev.get('critical',0)} H:{sev.get('high',0)} "
      f"M:{sev.get('medium',0)} L:{sev.get('low',0)}")
print(f"Scan  {last.get('target','-')} ({ago(last.get('finished_at') or last.get('started_at'))})")
if ib:
    print(f"Inbound  {ib.get('total',0)} hits / {ib.get('unique_sources',0)} src")
    top = (ib.get('top_sources') or [])[:1]
    if top:
        s = top[0]
        who = s.get('hostname') or s.get('src_ip')
        print(f"Top  {who} x{s.get('n')}")
PY

#!/usr/bin/env python3
"""Export findings metadata (no keys) to docs/data.json for the dashboard."""
import json, sqlite3
from pathlib import Path
from db import get_db

def export():
    conn = get_db()
    rows = conn.execute("""
        SELECT service, source, 
               date(first_seen, 'unixepoch') as ds,
               date(last_seen, 'unixepoch') as ls,
               valid, notified
        FROM findings 
        ORDER BY first_seen DESC
        LIMIT 1000
    """).fetchall()
    conn.close()

    by_service = {}
    by_source = {}
    timeline = {}
    live_count = 0
    total_count = 0

    for r in rows:
        svc = r["service"]
        src = r["source"]
        valid = r["valid"]
        total_count += 1
        if valid: live_count += 1
        by_service[svc] = by_service.get(svc, 0) + 1
        by_source[src] = by_source.get(src, 0) + 1
        ds = r["ds"]
        timeline[ds] = timeline.get(ds, 0) + 1

    out = {
        "total": total_count,
        "live": live_count,
        "by_service": dict(sorted(by_service.items(), key=lambda x: -x[1])),
        "by_source": dict(sorted(by_source.items(), key=lambda x: -x[1])),
        "timeline": dict(sorted(timeline.items())),
        "updated": sqlite3.datetime.datetime.now().isoformat(),
    }

    Path("docs").mkdir(exist_ok=True)
    Path("docs/data.json").write_text(json.dumps(out, indent=2))
    print(f"Exported {total_count} findings ({live_count} live)")

if __name__ == "__main__":
    export()

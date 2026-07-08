#!/usr/bin/env python3
import os, time, json
from pathlib import Path
from db import get_db, mark_validated, mark_notified
from patterns import validate_key
import validators

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT = os.getenv("TELEGRAM_CHAT", "")

def telegram_alert(text):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT: return
    import urllib.request
    try:
        data = json.dumps({"chat_id": TELEGRAM_CHAT, "text": text, "parse_mode": "Markdown"}).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data=data, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
    except: pass

def main():
    print(f"Re-validation run — {time.ctime()}")
    conn = get_db()
    rows = conn.execute("SELECT * FROM findings WHERE valid=1").fetchall()
    conn.close()
    print(f"  {len(rows)} live keys to re-check")
    for item in rows:
        key = item["key_value"]
        svc = item["service"]
        kh = item["key_hash"]
        result = validate_key(svc, key)
        if result == "error":
            print(f"  {svc}: error (network)")
            continue
        if result == True:
            print(f"  ✓ still live: {svc} | {key[:30]}...")
        else:
            print(f"  ✗ now revoked: {svc} | {key[:30]}...")
            mark_validated(kh, 0)
            msg = f"🔴 *KEY REVOKED*\nService: {svc}\nKey: `{key[:40]}...`\nSource: {item['source']}\nPreviously live, now returning 401."
            telegram_alert(msg)
    print("Done")

if __name__ == "__main__":
    main()

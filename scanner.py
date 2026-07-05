#!/usr/bin/env python3
import os, sys, time, json
from pathlib import Path
from db import init, get_unnotified_live, mark_notified
from patterns import extract_keys, validate_key
import validators
import sources

FINDINGS_FILE = Path(__file__).parent / "findings.log"
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
        print(f"  Telegram alert sent")
    except Exception as e:
        print(f"  Telegram error: {e}")

def write_findings(findings):
    with open(FINDINGS_FILE, "a") as f:
        for item in findings:
            f.write(json.dumps(item) + "\n")

def run_validation():
    print("\n===== VALIDATING LIVE KEYS =====")
    items = get_unnotified_live()
    print(f"  {len(items)} unnotified live keys in DB")
    for item in items:
        key = item["key_value"]
        svc = item["service"]
        result = validate_key(svc, key)
        if result == "error":
            print(f"  {svc}: {key[:40]}... error (network)")
            continue
        if result == "unknown":
            print(f"  {svc}: {key[:40]}... no validator")
            continue
        if result:
            msg = f"🔥 *LIVE API KEY FOUND*\nService: {svc}\nKey: `{key[:30]}...`\nSource: {item['source']}\nRepo: {item.get('repo', 'N/A')}"
            print(f"  ✓ LIVE: {svc} | {key[:40]}... | {item['source']}/{item.get('repo','?')[:40]}")
            telegram_alert(msg)
            mark_notified(key)
        else:
            print(f"  ✗ revoked: {svc} | {key[:40]}...")

def main():
    start = time.time()
    print(f"API Leak Scanner v2 — {time.ctime()}")
    print("=" * 50)
    init()

    deep = os.getenv("DEEP_SCAN", "0") == "1"

    sources.scan_events()
    sources.scan_gists()
    sources.scan_sourcegraph()

    if deep:
        if os.getenv("SHODAN_KEY"): sources.scan_shodan()
        if os.getenv("CENSYS_SECRET"): sources.scan_censys()
        sources.scan_pastebin()
        sources.scan_npm()
        sources.scan_pypi()
        sources.scan_dockerhub()
        if os.getenv("RUN_GITLEAKS"):
            sources.scan_gitleaks()

    run_validation()

    elapsed = time.time() - start
    print(f"\n===== DONE in {elapsed:.1f}s =====")

    # Write findings log for artifact
    from db import get_db
    conn = get_db()
    rows = conn.execute("SELECT * FROM findings WHERE valid=1").fetchall()
    conn.close()
    write_findings([dict(r) for r in rows])

if __name__ == "__main__":
    main()

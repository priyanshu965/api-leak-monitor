import sqlite3, time, hashlib
from pathlib import Path

DB_PATH = Path(__file__).parent / "scanner.db"

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    return conn

def init():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            service TEXT NOT NULL,
            key_value TEXT NOT NULL,
            source TEXT NOT NULL,
            repo TEXT DEFAULT '',
            file_path TEXT DEFAULT '',
            context TEXT DEFAULT '',
            entropy REAL DEFAULT 0,
            validated INTEGER DEFAULT 0,
            valid INTEGER DEFAULT 0,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            notified INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS seen_events (
            event_id TEXT NOT NULL,
            source TEXT NOT NULL,
            seen_at REAL NOT NULL,
            PRIMARY KEY (event_id, source)
        );
        CREATE INDEX IF NOT EXISTS idx_findings_valid ON findings(valid);
        CREATE INDEX IF NOT EXISTS idx_findings_notified ON findings(notified);
    """)
    conn.commit()
    conn.close()

def is_event_seen(event_id, source):
    conn = get_db()
    row = conn.execute("SELECT 1 FROM seen_events WHERE event_id=? AND source=?", (event_id, source)).fetchone()
    conn.close()
    return row is not None

def mark_event_seen(event_id, source):
    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO seen_events VALUES (?,?,?)", (event_id, source, time.time()))
    conn.commit()
    conn.close()

def key_hash(k):
    return hashlib.sha256(k.encode()).hexdigest()[:16]

def is_key_seen(key):
    conn = get_db()
    row = conn.execute("SELECT 1 FROM findings WHERE key_hash=?", (key_hash(key),)).fetchone()
    conn.close()
    return row is not None

def save_finding(service, key, source, repo="", file_path="", context="", entropy=0, validated=0, valid=0):
    conn = get_db()
    kh = key_hash(key)
    now = time.time()
    conn.execute("""
        INSERT INTO findings (key_hash, service, key_value, source, repo, file_path, context, entropy, validated, valid, first_seen, last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(key_hash) DO UPDATE SET
            last_seen=excluded.last_seen,
            source=CASE WHEN findings.source='events' AND excluded.source!='events' THEN excluded.source ELSE findings.source END
    """, (kh, service, key, source, repo, file_path, context, entropy, int(validated), int(valid) if validated else 0, now, now))
    conn.commit()
    conn.close()
    return kh

def mark_notified(key):
    conn = get_db()
    conn.execute("UPDATE findings SET notified=1 WHERE key_hash=?", (key_hash(key),))
    conn.commit()
    conn.close()

def get_unvalidated():
    conn = get_db()
    rows = conn.execute("SELECT * FROM findings WHERE validated=0").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def mark_validated(key_hash_val, valid):
    conn = get_db()
    conn.execute("UPDATE findings SET validated=1, valid=? WHERE key_hash=?", (int(valid), key_hash_val))
    conn.commit()
    conn.close()

def get_unnotified_live():
    conn = get_db()
    rows = conn.execute("SELECT * FROM findings WHERE valid=1 AND notified=0").fetchall()
    conn.close()
    return [dict(r) for r in rows]

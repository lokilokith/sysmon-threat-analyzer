import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "sysmon.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    if not DB_PATH.parent.exists():
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")

    # Ensure run_id exists in core tables
    tables_to_check = ["events", "detections", "behaviors"]
    for table in tables_to_check:
        try:
            cur.execute(f"SELECT run_id FROM {table} LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
            if cur.fetchone():
                print(f"[DB FIX] Adding run_id column to existing table: {table}")
                try:
                    cur.execute(f"ALTER TABLE {table} ADD COLUMN run_id TEXT")
                except sqlite3.OperationalError:
                    pass 

    # correlations table (detail)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            corr_id TEXT,
            base_image TEXT,
            process_id INTEGER,
            start_time TEXT,
            end_time TEXT,
            event_ids TEXT,
            kill_chain_stage TEXT,
            severity TEXT,
            confidence INTEGER,
            description TEXT,
            explanation TEXT,
            computer TEXT,
            run_id TEXT
        )
        """
    )
    try:
        cur.execute("SELECT run_id FROM correlations LIMIT 1")
    except sqlite3.OperationalError:
          cur.execute("ALTER TABLE correlations ADD COLUMN run_id TEXT")

    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_corr_main
        ON correlations (corr_id, process_id, start_time, run_id)
        """
    )

    # incidents table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE,
            status TEXT,
            severity TEXT,
            confidence INTEGER,
            escalation TEXT,
            analyst TEXT,
            notes TEXT,
            created_at TEXT,
            updated_at TEXT,
            run_id TEXT
        )
        """
    )
    try:
        cur.execute("SELECT run_id FROM incidents LIMIT 1")
    except sqlite3.OperationalError:
          cur.execute("ALTER TABLE incidents ADD COLUMN run_id TEXT")

    # correlation_campaigns summary table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS correlation_campaigns (
            corr_id TEXT,
            run_id TEXT,
            base_image TEXT,
            computer TEXT,
            first_seen TEXT,
            last_seen TEXT,
            burst_count INTEGER,
            max_confidence INTEGER,
            highest_kill_chain TEXT,
            status TEXT DEFAULT 'active',
            description TEXT,
            PRIMARY KEY (corr_id, run_id)
        )
    """)

    conn.commit()
    conn.close()

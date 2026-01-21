from __future__ import annotations
import math
from collections import defaultdict
from pathlib import Path
import sqlite3
import datetime
import hashlib
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd
import uuid
import traceback  # Added for traceback printing

# --- YARA support ---
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from dashboard.event_parser import (
    parse_event,
    load_all_sources_from_xml,
    find_detections,
)

# -------------------------------------------------------------------
# CONSTANTS & MAPPINGS
# -------------------------------------------------------------------

# Helper for YARA detection mapping
MITRE_TO_KILL_CHAIN = {
    "Initial Access": ["Delivery"],
    "Execution": ["Execution"],
    "Persistence": ["Persistence"],
    "Privilege Escalation": ["Privilege Escalation"],
    "Defense Evasion": ["Defense Evasion"],
    "Credential Access": ["Credential Access"],
    "Discovery": ["Discovery"],
    "Lateral Movement": ["Lateral Movement"],
    "Collection": ["Collection"],
    "Command and Control": ["Command and Control"],
    "Exfiltration": ["Exfiltration"],
    "Impact": ["Actions on Objectives"],
}

# -------------------------------------------------------------------
# SNAPSHOT CACHE (DISABLED)
# -------------------------------------------------------------------

def get_analysis_snapshot(run_id: str) -> Optional[Dict[str, Any]]:
    """Snapshotting disabled. Always return None."""
    return None

def set_analysis_snapshot(run_id: str, result: Dict[str, Any]) -> None:
    """Snapshotting disabled. Do nothing."""
    pass

def clear_analysis_snapshot(run_id: str) -> None:
    """Snapshotting disabled. Do nothing."""
    pass

# --- Static ranking helpers for Top-10 dangerous bursts ---
KILL_CHAIN_ORDER = [
    "Background",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Command and Control",
    "Actions on Objectives",
]
KILLCHAIN_ORDER_FOR_RANK = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

def rank_dangerous_bursts(bursts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return top 10 most dangerous bursts based on risk, kill-chain, correlation, and volume."""
    ranked = sorted(
        bursts,
        key=lambda b: (
            -int(b.get("peak_score", 0) or 0),
            -KILLCHAIN_ORDER_FOR_RANK.get(b.get("kill_chain_stage") or "Background", 0),
            -int(b.get("total_count", 0) or 0),
        ),
    )
    return ranked[:10]

# --- Local DB helpers to avoid circular import with dashboard.app ---
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "sysmon.db"

print("[DB] Using DB at:", DB_PATH.resolve())

def get_db_connection():
    return sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)

# -------------------------------------------------------------------
# NEW: Ensure Campaign Tables Exist at Import Time
# -------------------------------------------------------------------
def ensure_campaign_tables():
    conn = get_db_connection()
    cur = conn.cursor()

    # Summary table: correlation_campaigns
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

    # Detail table: correlations
    cur.execute("""
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            corr_id TEXT,
            run_id TEXT,
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
            computer TEXT
        )
    """)

    conn.commit()
    conn.close()

# Call immediately to guarantee table existence
ensure_campaign_tables()

# -------------------------------------------------------------------
# Helper: YARA Loader
# -------------------------------------------------------------------
def load_yara_rules(rules_path: Optional[Path]):
    if not rules_path or not rules_path.exists():
        return None

    if rules_path.suffix.lower() not in (".yar", ".yara"):
        return None

    if not YARA_AVAILABLE:
        raise RuntimeError("python-yara not installed")

    try:
        return yara.compile(filepath=str(rules_path))
    except yara.SyntaxError as e:
        raise RuntimeError(f"Invalid YARA rule: {e}") from e

# -------------------------------------------------------------------
# Helper: Behavior Generation (Internal)
# -------------------------------------------------------------------
def _generate_behaviors(df: pd.DataFrame, run_id: str) -> pd.DataFrame:
    """
    Transform raw events into the behaviors format required for analysis.
    """
    behaviors = []
    # Ensure we iterate over the dataframe safely
    for _, r in df.iterrows():
        eid_raw = r.get("event_id")
        try:
            eid = str(int(float(eid_raw)))
        except:
            continue

        # Map EventID to Behavior Type
        btype = None
        if eid == "1": btype = "execution"
        elif eid == "3": btype = "network"
        elif eid in ("11", "15"): btype = "file"
        elif eid in ("12", "13", "14"): btype = "registry"
        
        if not btype:
            continue

        # Create behavior record matching DB schema
        behaviors.append({
            "run_id": run_id,
            "behavior_id": f"{run_id}-{eid}-{uuid.uuid4().hex[:8]}",
            "behavior_type": btype,
            "event_time": r.get("event_time"), # Normalized time from Events DF
            "image": r.get("image"),
            "parent_image": r.get("parent_image"),
            "command_line": r.get("command_line"),
            "user": r.get("user"),
            "process_id": r.get("pid"),
            "parent_process_id": r.get("ppid"),
            "computer": r.get("computer"),
            "source_ip": r.get("src_ip"),
            "destination_ip": r.get("destination_ip"),
            "destination_port": r.get("destination_port"),
            "target_filename": r.get("file_path") or r.get("target_filename"),
            "raw_event_id": eid
        })

    return pd.DataFrame(behaviors)

# -------------------------------------------------------------------
# NEW UPLOAD HANDLERS
# -------------------------------------------------------------------

def ingest_upload(xml_path: Path, rules_path: Optional[Path] = None) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Parse XML into events/behaviors for a NEW run_id. No DB writes here."""
    if not xml_path.exists():
        raise FileNotFoundError(f"Sysmon XML not found: {xml_path}")

    run_id = uuid.uuid4().hex  # NEW run for every upload

    rows = load_all_sources_from_xml(xml_path)
    if not rows:
        raise RuntimeError("Upload aborted: XML contained no events.")

    events_df = pd.DataFrame(rows)

    if "event_id" not in events_df.columns:
        raise RuntimeError("event_id column missing in parsed XML")

    events_df["event_id"] = events_df["event_id"].astype(str).str.strip()
    events_df = events_df[events_df["event_id"].notna() & (events_df["event_id"] != "None")]
    if events_df.empty:
        raise RuntimeError("All events dropped — EventID missing/invalid in XML")

    events_df["run_id"] = run_id
    events_df["event_time"] = pd.to_datetime(events_df["utc_time"], errors="coerce", utc=True)
    events_df = events_df.dropna(subset=["event_time"])

    events_df = events_df.rename(columns={
        "commandline": "command_line",
        "processid": "pid",
        "parentprocessid": "ppid",
    })

    # Load YARA rules (Phase 4a only)
    yara_rules = load_yara_rules(rules_path)

    # --- YARA (per-upload, per-event, stateless) ---
    events_df["yara_hits"] = None
    if yara_rules:
        def run_yara(row):
            # Metadata-only scan: NOT file/memory AV
            scan_data = " ".join(
                str(row.get(k) or "")
                for k in ("image", "command_line", "target_filename", "parent_image", "destination_ip")
            )
            try:
                matches = yara_rules.match(data=scan_data)
                if not matches:
                    return None

                hits = []
                for m in matches:
                    meta = getattr(m, "meta", {}) or {}
                    hits.append({
                        "rule_name": m.rule,
                        "rule_id": meta.get("rule_id", m.rule),
                        "description": meta.get("description"),
                        "mitre_id": meta.get("mitre_id"),
                        "mitre_tactic": meta.get("mitre_tactic"),
                        "severity": (meta.get("severity") or "high").lower(),
                    })
                return hits
            except Exception:
                return None

        events_df["yara_hits"] = events_df.apply(run_yara, axis=1)

        hit_mask = events_df["yara_hits"].notna()

        # Hard signal: YARA overrides severity to the max of its hits
        def pick_severity(hits):
            order = {"low": 1, "medium": 2, "high": 3}
            if not hits:
                return "high"
            return max((h.get("severity", "high").lower() for h in hits),
                       key=lambda s: order.get(s, 3))

        events_df.loc[hit_mask, "severity"] = events_df.loc[hit_mask, "yara_hits"].apply(pick_severity)
        events_df.loc[hit_mask, "tags"] = (
            events_df.loc[hit_mask, "tags"].fillna("") + ",YARA_MATCH"
        )

    # behaviours already created
    behaviors_df = _generate_behaviors(events_df, run_id)

    # --- Detections: YAML rules engine ---
    detections_df = find_detections(events_df)
    print("[DEBUG] ingest_upload rules detections_df rows:", len(detections_df))
    if not detections_df.empty:
        detections_df["run_id"] = run_id
    else:
        detections_df = pd.DataFrame(columns=[
            "run_id", "rule_id", "rule_name", "mitre_id", "mitre_tactic",
            "kill_chain_stage", "utc_time", "image", "event_id",
            "description", "severity", "computer", "process_id",
            "parent_process_id", "parent_image", "source_ip",
            "source_port", "destination_ip", "destination_port",
            "target_filename", "confidence_score",
        ])

    # --- Detections: YARA engine (Phase 4a) ---
    yara_rows = []
    hit_mask = events_df["yara_hits"].notna()
    for _, r in events_df[hit_mask].iterrows():
        hits = r["yara_hits"] or []

        # Confidence scaling: 1/2/3+ hits → 60/75/90
        n_hits = len(hits)
        if n_hits <= 0:
            continue
        if n_hits == 1:
            base_conf = 60
        elif n_hits == 2:
            base_conf = 75
        else:
            base_conf = 90

        for h in hits:
            yara_rows.append({
                "run_id": run_id,
                "rule_id": h.get("rule_id"),
                "rule_name": h.get("rule_name"),
                "mitre_id": h.get("mitre_id"),          # parsed from meta, not fake
                "mitre_tactic": h.get("mitre_tactic"),  # parsed from meta
                "kill_chain_stage": (MITRE_TO_KILL_CHAIN.get(h.get("mitre_tactic")) or ["Execution"])[0],
                "utc_time": r.get("utc_time"),
                "image": r.get("image"),
                "event_id": r.get("event_id"),
                "description": h.get("description") or r.get("description"),
                "severity": r.get("severity"),
                "computer": r.get("computer"),
                "process_id": r.get("process_id"),
                "parent_process_id": r.get("parent_process_id"),
                "parent_image": r.get("parent_image"),
                "source_ip": r.get("source_ip"),
                "source_port": r.get("source_port"),
                "destination_ip": r.get("destination_ip"),
                "destination_port": r.get("destination_port"),
                "target_filename": r.get("target_filename"),
                "confidence_score": base_conf,
            })
        
    if yara_rows:
        yara_df = pd.DataFrame(yara_rows)
        detections_df = pd.concat([detections_df, yara_df], ignore_index=True)
        
    print("[DEBUG] ingest_upload total detections_df rows (rules+YARA):", len(detections_df))

    return events_df, detections_df, behaviors_df

def persist_case(events_df: pd.DataFrame, detections_df: pd.DataFrame, behaviors_df: pd.DataFrame) -> None:
    """Write this run's events/behaviors/detections into SQLite."""
    if events_df.empty:
        raise RuntimeError("No events to persist")

    run_ids = events_df["run_id"].dropna().unique().tolist()
    if len(run_ids) != 1:
        raise RuntimeError(f"Expected exactly one run_id, got: {run_ids}")
    run_id = run_ids[0]

    conn = get_db_connection()
    try:
        cur = conn.cursor()

        # Events table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_uid TEXT, run_id TEXT, event_time TEXT, event_id TEXT, image TEXT,
                parent_image TEXT, command_line TEXT, user TEXT, pid TEXT, ppid TEXT,
                src_ip TEXT, dst_ip TEXT, dst_port TEXT, file_path TEXT, severity TEXT,
                computer TEXT, description TEXT, tags TEXT, destination_ip TEXT,
                source_port TEXT, target_filename TEXT, process_id TEXT, parent_process_id TEXT
            )
        """)
        cur.execute("PRAGMA table_info(events)")
        event_cols = [info[1] for info in cur.fetchall()]

        ev = events_df.copy()
        if "utc_time" in ev.columns and "utc_time" not in event_cols:
            ev = ev.drop(columns=["utc_time"])
        
        # Remove runtime columns before persisting
        if "yara_hits" in ev.columns:
            ev = ev.drop(columns=["yara_hits"])

        cols_to_write = list(set(ev.columns).intersection(event_cols))
        ev[cols_to_write].to_sql("events", conn, if_exists="append", index=False)

        # Behaviors table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS behaviors (
                run_id TEXT, behavior_id TEXT, behavior_type TEXT, event_time TEXT,
                image TEXT, parent_image TEXT, command_line TEXT, user TEXT,
                process_id TEXT, parent_process_id TEXT, computer TEXT,
                source_ip TEXT, destination_ip TEXT, destination_port TEXT,
                target_filename TEXT, raw_event_id TEXT
            )
        """)
        cur.execute("PRAGMA table_info(behaviors)")
        beh_cols = [info[1] for info in cur.fetchall()]

        if not behaviors_df.empty:
            bh = behaviors_df.copy()
            bh_cols = list(set(bh.columns).intersection(beh_cols))
            bh[bh_cols].to_sql("behaviors", conn, if_exists="append", index=False)

        # --- Detections table ---
        if not detections_df.empty:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    rule_id TEXT,
                    rule_name TEXT,
                    mitre_id TEXT,
                    mitre_tactic TEXT,
                    kill_chain_stage TEXT,
                    event_time TEXT,
                    utc_time TEXT,
                    image TEXT,
                    event_id TEXT,
                    description TEXT,
                    severity TEXT,
                    computer TEXT,
                    process_id TEXT,
                    parent_process_id TEXT,
                    parent_image TEXT,
                    source_ip TEXT,
                    source_port TEXT,
                    destination_ip TEXT,
                    destination_port TEXT,
                    target_filename TEXT,
                    confidence_score REAL
                )
            """)
            cur.execute("PRAGMA table_info(detections)")
            det_cols = [info[1] for info in cur.fetchall()]

            dt = detections_df.copy()
            if "run_id" not in dt.columns:
                dt["run_id"] = run_id

            cols_to_write = list(set(dt.columns).intersection(det_cols))
            dt[cols_to_write].to_sql("detections", conn,
                                     if_exists="append", index=False)

        conn.commit()
    finally:
        conn.close()

# -------------------------------------------------------------------

def update_campaign_status_lifecycle() -> None:
    """
    Lifecycle Logic.
    Updates campaign status based on last_seen activity.
    - Active -> Dormant if > 24 hours silent.
    """
    if not DB_PATH.exists():
        return

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Check if table exists first
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='correlation_campaigns'")
        if not cur.fetchone():
            return

        # Mark dormant if last_seen is older than 24 hours and currently active
        yesterday = (datetime.datetime.utcnow() - datetime.timedelta(hours=24)).isoformat()
        cur.execute("""
            UPDATE correlation_campaigns 
            SET status = 'dormant' 
            WHERE status = 'active' AND last_seen < ?
        """, (yesterday,))
        conn.commit()
    except Exception as e:
        print(f"[WARN] Campaign lifecycle update failed: {e}")
    finally:
        conn.close()

def persist_auto_correlation(burst: Dict[str, Any], run_id: str) -> None:
    """
    Persist aggregated campaigns with the specific run_id.
    """
    print(f"[DEBUG] persist_auto_correlation CALLED {run_id} {burst.get('correlation_id')}")

    if not DB_PATH.exists():
        print("WARN DB_PATH missing in persist_auto_correlation, forcing creation")

    conn = get_db_connection()
    cur = conn.cursor()

    # 1. Update Schema (Auto-Heal if column missing)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS correlation_campaigns (
            corr_id TEXT,
            run_id TEXT,  # ✅ We need this column
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

    # Auto-patch existing table if run_id is missing
    try:
        cur.execute("SELECT run_id FROM correlation_campaigns LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cur.execute("ALTER TABLE correlation_campaigns ADD COLUMN run_id TEXT")
        except:
            pass # Table might just be created or empty

    # Also ensure the detailed correlations table exists with run_id
    cur.execute("""
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            corr_id TEXT,
            run_id TEXT,
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
            computer TEXT
        )
    """)
    
    # Auto-patch existing correlations table
    try:
        cur.execute("SELECT run_id FROM correlations LIMIT 1")
    except sqlite3.OperationalError:
        try:
              cur.execute("ALTER TABLE correlations ADD COLUMN run_id TEXT")
        except:
              pass

    corr_id = burst["correlation_id"]
    now_str = datetime.datetime.utcnow().isoformat()
    new_stage = burst.get("kill_chain_stage") or "Execution"
    new_conf = int(burst.get("risk_score", 0))

    try:
        # Check if campaign exists FOR THIS RUN
        cur.execute(
            "SELECT burst_count, max_confidence, highest_kill_chain FROM correlation_campaigns WHERE corr_id = ? AND run_id = ?", 
            (corr_id, run_id)
        )
        row = cur.fetchone()

        if row:
            # Update existing
            current_count, current_max_conf, current_stage = row
            final_stage = promote_stage(current_stage, new_stage)
            final_conf = max(current_max_conf, new_conf)
            final_count = current_count + 1

            cur.execute("""
                UPDATE correlation_campaigns 
                SET burst_count = ?, last_seen = ?, max_confidence = ?, highest_kill_chain = ?, status = 'active'
                WHERE corr_id = ? AND run_id = ?
            """, (final_count, now_str, final_conf, final_stage, corr_id, run_id))
        else:
            # Insert new (strictly associated with run_id)
            cur.execute("""
                INSERT INTO correlation_campaigns 
                (corr_id, run_id, base_image, computer, first_seen, last_seen, burst_count, max_confidence, highest_kill_chain, status, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                corr_id,
                run_id, 
                burst.get("image"),
                burst.get("computer"),
                now_str, now_str, 1, new_conf, new_stage, "active",
                f"Auto-correlated campaign for {burst.get("image")}"
            ))

        # --- B. Update Detail Level ---
        rich_description = f"[{new_stage}] Risk:{new_conf}% - Detected sequence involving {burst.get('count', 0)} events."
        
        cur.execute("""
            INSERT INTO correlations
            (corr_id, run_id, base_image, start_time, end_time, description, event_ids, computer)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            corr_id,
            run_id,
            burst.get("image"),
            burst.get("start_time"),
            burst.get("end_time"),
            rich_description,
            ",".join(str(e) for e in burst.get("event_ids", [])),
            burst.get("computer"),
        ))
        
        conn.commit()
    except Exception as e:
        print(f"[WARN] Correlation persist failed: {repr(e)}")
        traceback.print_exc()
    finally:
        conn.close()

def load_correlation_campaigns(run_id: str) -> pd.DataFrame:
    """Load aggregated campaign data for UI, strictly filtered by run_id."""
    if not DB_PATH.exists():
        return pd.DataFrame()

    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            "SELECT * FROM correlation_campaigns WHERE run_id = ? ORDER BY last_seen DESC", 
            conn,
            params=(run_id,)
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

def load_events(run_id: str) -> pd.DataFrame:
    """Load raw Sysmon events from SQLite into a normalized DataFrame."""
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            """
            SELECT *
            FROM events
            WHERE run_id = ?
            ORDER BY event_time DESC
            """,
            conn,
            params=(run_id,),
        )
    except Exception as e:
        print(f"[WARN] Failed to load events: {e}")
        df = pd.DataFrame()
        
    conn.close()

    # Rename 'event_time' -> 'utc_time' ONLY for UI compatibility
    if "event_time" in df.columns:
        df = df.rename(columns={"event_time": "utc_time"})

    # Normalization logic
    df = df.rename(
        columns={
            "pid": "process_id",
            "ppid": "parent_process_id",
            "file_path": "target_filename",
            "src_ip": "source_ip",
            "dst_ip": "destination_ip",
            "command_line": "commandline",
        }
    )

    for col in ["description", "computer", "tags"]:
        if col not in df.columns:
            df[col] = ""

    # Safe tag splitting (handle NaN)
    if "tags" in df.columns:
        df["tags"] = df["tags"].fillna("").apply(
            lambda x: [t for t in str(x).split(",") if t]
        )

    if "utc_time" in df.columns:
        df["_parsed_time"] = pd.to_datetime(df["utc_time"], errors="coerce", utc=True)
    else:
        df["_parsed_time"] = pd.NaT

    return df

def load_detections(run_id: str) -> pd.DataFrame:
    """
    Load detection rows from SQLite for a specific run_id.
    """
    empty_schema = pd.DataFrame(
        columns=[
            "rule_id", "rule_name", "mitre_id", "mitre_tactic",
            "kill_chain_stage", "utc_time", "image", "event_id",
            "description", "severity", "computer", "process_id",
            "parent_process_id", "parent_image", "source_ip",
            "source_port", "destination_ip", "destination_port",
            "target_filename", "confidence_score",
        ]
    )

    if not DB_PATH.exists():
        return empty_schema

    conn = get_db_connection()
    try:
        tables_df = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table'", conn)
        tables = tables_df["name"].tolist() if not tables_df.empty else []

        target_table = None
        if "detections" in tables:
            target_table = "detections"
        elif "sigma_matches" in tables:
            target_table = "sigma_matches"
        
        if not target_table:
            conn.close()
            return empty_schema

        query = f"SELECT * FROM {target_table} WHERE run_id = ? ORDER BY event_time DESC"
        det = pd.read_sql_query(query, conn, params=(run_id,))
            
    except Exception as e:
        print(f"[WARN] Failed to load detections: {e}")
        conn.close()
        return empty_schema

    conn.close()

    # UI requires utc_time
    if "event_time" in det.columns:
        det = det.rename(columns={"event_time": "utc_time"})

    # Ensure all columns exist
    for col in empty_schema.columns:
        if col not in det.columns:
            det[col] = None

    return det

def load_correlations(run_id: str) -> pd.DataFrame:
    """Load multi-stage correlation rows for a specific run."""
    if not DB_PATH.exists():
        return pd.DataFrame()

    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            "SELECT * FROM correlations WHERE run_id = ?", 
            conn, 
            params=(run_id,)
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

def load_correlations_detail(run_id: str) -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            """
            SELECT *
            FROM correlations
            WHERE run_id = ?
            ORDER BY confidence DESC, start_time ASC
            LIMIT 10
            """,
            conn,
            params=(run_id,),
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

def load_behaviors(run_id: str) -> pd.DataFrame:
    """Load behavior-level events for grouping into bursts for a specific run."""
    if not DB_PATH.exists():
        return pd.DataFrame()

    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            "SELECT * FROM behaviors WHERE run_id = ? ORDER BY event_time DESC",
            conn,
            params=(run_id,)
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

def load_incident_row(incident_id: str) -> Optional[dict]:
    """Helper used by app routes, kept here to centralize DB access."""
    if not DB_PATH.exists():
        return None
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT incident_id, status, severity, confidence, escalation, analyst, "
            "notes, created_at, updated_at FROM incidents WHERE incident_id = ?",
            (incident_id,),
        )
        row = cur.fetchone()
    except Exception:
        row = None
        
    conn.close()
    if not row:
        return None
    keys = [
        "incident_id", "status", "severity", "confidence", "escalation",
        "analyst", "notes", "created_at", "updated_at",
    ]
    return dict(zip(keys, row))

def upsert_incident_row(
    incident_id: str,
    status: str,
    severity: str,
    confidence: int,
):
    """Minimal upsert, used elsewhere in app."""
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO incidents (incident_id, status, severity, confidence, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(incident_id) DO UPDATE SET
        confidence = excluded.confidence,
        updated_at = excluded.updated_at
        """,
        (incident_id, status, severity, confidence, now, now),
    )
    conn.commit()
    conn.close()

# -------------------------------------------------------------------
# Behavior baseline persistence (AI layer backing store)
# -------------------------------------------------------------------
def load_behavior_baseline() -> Dict[Tuple[str, str, str, str, int], Dict[str, Any]]:
    """Load persisted baseline stats from SQLite into a dict."""
    if not DB_PATH.exists():
        return {}
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            "SELECT * FROM behavior_baseline",
            conn,
        )
    except Exception:
        conn.close()
        return {}
    conn.close()

    baseline: Dict[Tuple[str, str, str, str, int], Dict[str, Any]] = {}
    for _, row in df.iterrows():
        key = (
            row.get("computer") or row.get("host") or "unknown_host",  # host dimension
            row["process_name"],
            row["user_type"],
            row["parent_process"],
            int(row["hour_bucket"]),
        )
        
        # Convert DB storage format (Avg/Var) to Algorithm format (Mean/M2)
        # Variance = M2 / (n - 1)  => M2 = Variance * (n - 1)
        count = int(row.get("count_samples", 0) or 0)
        var = float(row.get("var_exec", 0.0) or 0.0)
        m2 = var * (count - 1) if count > 1 else 0.0

        baseline[key] = {
            "count_samples": count,
            "mean_exec": float(row.get("avg_exec", 0.0) or 0.0), # Map DB 'avg' to algo 'mean'
            "m2_exec": m2,                                       # Calculated M2
            "avg_cmd_len": float(row.get("avg_cmd_len", 0.0) or 0.0),
            "avg_followup": float(row.get("avg_followup", 0.0) or 0.0),
            "seen_days": int(row.get("seen_days", 0) or 0),
        }

    return baseline

def persist_behavior_baseline(
    baseline_state: Dict[Tuple[str, str, str, str, int], Dict[str, Any]]
) -> None:
    """Persist updated baseline stats back into SQLite."""
    if not baseline_state:
        return

    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    conn = get_db_connection()
    cur = conn.cursor()

    # 1. Define schema including 'computer'
    table_schema = """
        CREATE TABLE IF NOT EXISTS behavior_baseline (
            computer        TEXT NOT NULL DEFAULT 'unknown_host',
            process_name    TEXT NOT NULL,
            user_type       TEXT NOT NULL,
            parent_process  TEXT NOT NULL,
            hour_bucket     INTEGER NOT NULL,
            avg_exec        REAL NOT NULL,
            var_exec        REAL NOT NULL,
            avg_cmd_len     REAL NOT NULL,
            avg_followup    REAL NOT NULL,
            count_samples   INTEGER NOT NULL,
            seen_days       INTEGER NOT NULL DEFAULT 1,
            last_updated    TEXT NOT NULL,
            PRIMARY KEY (computer, process_name, user_type, parent_process, hour_bucket)
        )
    """
    cur.execute(table_schema)

    # 2. Schema Migration Check: If table exists but lacks 'computer', recreate it.
    try:
        cur.execute("SELECT computer FROM behavior_baseline LIMIT 1")
    except sqlite3.OperationalError:
        # Column missing -> drop and recreate
        cur.execute("DROP TABLE behavior_baseline")
        cur.execute(table_schema)

    # 3. Insert/Update with correct 5-variable unpacking
    for (computer, pname, utype, parent, hour), entry in baseline_state.items():
        
        # Convert Algorithm format (Mean/M2) to DB format (Avg/Var)
        count = int(entry["count_samples"])
        mean = float(entry.get("mean_exec", 0.0)) # Use 'mean' from update_local_baseline
        m2 = float(entry.get("m2_exec", 0.0))
        
        # Variance calculation
        variance = m2 / (count - 1) if count > 1 else 0.0
        
        seen_days = int(entry.get("seen_days", 1) or 1)

        cur.execute(
            """
            INSERT INTO behavior_baseline (
                computer, process_name, user_type, parent_process, hour_bucket,
                avg_exec, var_exec, avg_cmd_len, avg_followup,
                count_samples, seen_days, last_updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(computer, process_name, user_type, parent_process, hour_bucket)
            DO UPDATE SET
                avg_exec      = excluded.avg_exec,
                var_exec      = excluded.var_exec,
                avg_cmd_len   = excluded.avg_cmd_len,
                avg_followup  = excluded.avg_followup,
                count_samples = excluded.count_samples,
                seen_days     = ?,
                last_updated  = excluded.last_updated
            """,
            (
                computer, pname, utype, parent, hour,
                mean,        # avg_exec
                variance,    # var_exec
                float(entry["avg_cmd_len"]),
                float(entry["avg_followup"]),
                count,
                seen_days,
                now,
                seen_days # passed for the UPDATE clause
            ),
        )
    conn.commit()
    conn.close()

def load_execution_baseline() -> pd.DataFrame:
    """
    Load aggregated execution baseline stats for UI display.
    Reads from the behavior_baseline table and aggregates by process.
    """
    if not DB_PATH.exists():
        return pd.DataFrame(columns=["image", "execution_count", "avg_len", "last_updated"])

    conn = get_db_connection()
    try:
        # Aggregate by image (process_name) to show global stats in UI
        # UI expects: 'execution_count'
        df = pd.read_sql_query(
            """
            SELECT 
                process_name as image,
                SUM(count_samples) as execution_count,
                AVG(avg_cmd_len) as avg_len,
                MAX(last_updated) as last_updated
            FROM behavior_baseline
            GROUP BY process_name
            ORDER BY execution_count DESC
            """, 
            conn
        )
    except Exception:
        df = pd.DataFrame(columns=["image", "execution_count", "avg_len", "last_updated"])
    finally:
        conn.close()

    return df

# === Event-level explanation mapping (SOC knowledge, not ML) ===
EVENT_EXPLANATION_MAP_DETAILED: Dict[int, Dict[str, Any]] = {
    1: {
        "name": "Process Creation",
        "why_dangerous": (
            "Unexpected or high-frequency process execution may indicate malware, "
            "script abuse, or misuse of living-off-the-land binaries (LOLBins)."
        ),
        "risk_indicators": [
            "Unusual parent process",
            "Encoded or obfuscated command line",
            "Execution outside normal working hours",
        ],
        "analyst_actions": [
            "Review full command line",
            "Check parent-child process relationship",
            "Verify file hash reputation and signing status",
        ],
    },
    3: {
        "name": "Network Connection",
        "why_dangerous": (
            "Outbound connections can indicate command-and-control, data exfiltration, "
            "or lateral movement."
        ),
        "risk_indicators": [
            "External destination IP or rare domain",
            "Repeated beacon-like connection pattern",
            "Connection from unusual process",
        ],
        "analyst_actions": [
            "Check destination IP/domain reputation",
            "Inspect traffic frequency and pattern",
            "Confirm whether connection is business-related",
        ],
    },
    11: {
        "name": "File Creation",
        "why_dangerous": (
            "New files written by suspicious processes may represent payloads, "
            "droppers, or tools used post-compromise."
        ),
        "risk_indicators": [
            "Executable dropped in user or temp directory",
            "File created shortly after process execution",
            ],
        "analyst_actions": [
            "Analyze file hash and path",
            "Verify publisher/signature if present",
            "Scan in AV or sandbox",
        ],
    },
    13: {
        "name": "Registry Modification",
        "why_dangerous": (
            "Registry changes can implement persistence or modify security-relevant "
            "configuration."
        ),
        "risk_indicators": [
            "Autorun or startup registry locations",
            "Modification by non-system process",
        ],
        "analyst_actions": [
            "Review modified keys/values",
            "Check if change persists across reboot",
            "Validate with system owner or baseline",
        ],
    },
}

def enrich_burst_with_event_explanations(
    burst: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Attach static SOC explanations for each relevant event ID in this burst."""
    explanations: List[Dict[str, Any]] = []
    raw_ids = burst.get("event_ids") or []

    for eid in raw_ids:
        try:
            eid_int = int(eid)
        except (TypeError, ValueError):
            continue
        meta = EVENT_EXPLANATION_MAP_DETAILED.get(eid_int)
        if not meta:
            continue
        explanations.append(
            {
                "eventid": eid_int,
                "**meta": meta,
            }
        )
    return explanations

# -------------------------------------------------------------------
# Full analysis engine
# -------------------------------------------------------------------
def promote_stage(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if not a:
        return b
    if not b:
        return a
    if a not in KILL_CHAIN_ORDER and b not in KILL_CHAIN_ORDER:
        return a or b
    if a not in KILL_CHAIN_ORDER:
        return b
    if b not in KILL_CHAIN_ORDER:
        return a
    return b if KILL_CHAIN_ORDER.index(b) > KILL_CHAIN_ORDER.index(a) else a

# --- Helper Logic for External IP & Time ---
def is_external_ip(ip: str) -> bool:
    # Explicitly mention limitation regarding RFC1918/IPv6/CGNAT
    # NOTE: Simplified RFC1918 check; IPv6 and CGNAT not handled (lab scope)
    if not ip:
        return False
    ip = str(ip)
    return not ip.startswith(
        (
            "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "127.", "::1",
        )
    )

def baseline_is_mature(entry: Optional[Dict[str, Any]]) -> bool:
    if not entry:
        return False
    return int(entry.get("count_samples", 0) or 0) >= 20

def time_overlap(burst: Dict[str, Any], corr: Dict[str, Any], window_seconds: int = 900) -> bool:
    """Check if a burst overlaps significantly with a correlation record time window."""
    try:
        b_start = pd.to_datetime(burst.get("start_time"), utc=True)
        # c_start = pd.to_datetime(corr.get("start_time"), utc=True) # Not strictly needed if checking end overlap
        c_end = pd.to_datetime(corr.get("end_time"), utc=True)

        if pd.isna(b_start) or pd.isna(c_end):
            return False

        # If the burst started within N seconds of the correlation ending (or during it)
        diff = (b_start - c_end).total_seconds()
        return abs(diff) <= window_seconds
    except Exception:
        return False

# --- Core Modules (Refactored from monolithic function) ---
def _build_bursts(df: pd.DataFrame, beh_df: pd.DataFrame, run_id: str) -> List[Dict[str, Any]]:
    """Step 2: Convert events/behaviors into grouped bursts."""
    if not beh_df.empty and "event_time" in beh_df.columns:
        base_beh = beh_df.copy()
        base_beh["_parsed_time"] = pd.to_datetime(
            base_beh["event_time"], errors="coerce", utc=True
        )
        base_beh = base_beh.dropna(subset=["_parsed_time"])

        # Fill missing basics
        base_beh["image"] = base_beh["image"].fillna("unknown_process")
        base_beh["process_id"] = base_beh["process_id"].fillna("unknown_pid")
        base_beh["computer"] = base_beh["computer"].fillna("unknown_host")
        base_beh["user"] = base_beh["user"].fillna("unknown_user")

        base_beh = base_beh.sort_values("_parsed_time", ascending=True)

        grouped_rows: List[Dict[str, Any]] = []
        current: Optional[Dict[str, Any]] = None
        current_key: Optional[Tuple[Any, Any, Any, Any]] = None

        for _, b in base_beh.iterrows():
            img = b.get("image")
            pid = b.get("process_id")
            host = b.get("computer")
            user = b.get("user")
            btime = b.get("_parsed_time")
            # ✅ FIX 4: Cast behavior extraction event_id to string
            eid = str(b.get("raw_event_id"))
            btype = b.get("behavior_type")

            if pd.isna(btime):
                continue

            key = (img, pid, host, user)

            if current is None:
                current_key = key
                current = {
                    "start_time": btime.isoformat(),
                    "end_time": btime.isoformat(),
                    "count": 1,
                    # Track executions separately from event count
                    "exec_event_count": 1 if btype == "execution" else 0,
                    "image": img,
                    "kill_chain_stage": "Execution",  # placeholder
                    "event_ids": [eid],
                    "mitre_ids": [],
                    "mitre_tactics": [],
                    "descriptions": [],
                    "has_correlation": False,
                    "severity": None,
                    "type": "telemetry",
                    "source_ip": b.get("source_ip"),
                    "destination_ip": b.get("destination_ip"),
                    "destination_port": b.get("destination_port"),
                    "target_filename": b.get("target_filename"),
                    "has_exec": btype == "execution",
                    "has_net": btype == "network",
                    "has_file": btype == "file",
                    "has_reg": btype == "registry",
                    "net_event_count": 1 if btype == "network" else 0,
                    "process_id": pid,
                    "parent_process_id": b.get("parent_process_id"),
                    "parent_image": b.get("parent_image"),
                    "computer": host,
                    "user": user,
                    "hosts": [host] if host else [],
                    "users": [user] if user else [],
                    # ✅ FIX: Add Burst ID with run_id
                    "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
                }
            else:
                same_key = key == current_key
                prev_time = pd.to_datetime(
                    current["end_time"], errors="coerce", utc=True
                )
                this_time = btime
                close_in_time = (
                    pd.notna(prev_time)
                    and pd.notna(this_time)
                    and (this_time - prev_time).total_seconds() <= 900
                )

                if same_key and close_in_time:
                    current["end_time"] = this_time.isoformat()
                    current["count"] += 1
                    current["event_ids"].append(eid)
                    if btype == "execution":
                        current["exec_event_count"] = current.get("exec_event_count", 0) + 1

                    if not current.get("source_ip") and b.get("source_ip"):
                        current["source_ip"] = b.get("source_ip")
                    if not current.get("destination_ip") and b.get("destination_ip"):
                        current["destination_ip"] = b.get("destination_ip")
                    if (
                        not current.get("destination_port")
                        and b.get("destination_port")
                    ):
                        current["destination_port"] = b.get("destination_port")
                    if (
                        not current.get("target_filename")
                        and b.get("target_filename")
                    ):
                        current["target_filename"] = b.get("target_filename")
                    if btype == "execution":
                        current["has_exec"] = True
                    elif btype == "network":
                        current["has_net"] = True
                        current["net_event_count"] = (
                            current.get("net_event_count", 0) + 1
                        )
                    elif btype == "file":
                        current["has_file"] = True
                    elif btype == "registry":
                        current["has_reg"] = True
                else:
                    grouped_rows.append(current)
                    current_key = key
                    current = {
                        "start_time": btime.isoformat(),
                        "end_time": btime.isoformat(),
                        "count": 1,
                        "exec_event_count": 1 if btype == "execution" else 0,
                        "image": img,
                        "kill_chain_stage": "Execution",
                        "event_ids": [eid],
                        "mitre_ids": [],
                        "mitre_tactics": [],
                        "descriptions": [],
                        "has_correlation": False,
                        "severity": None,
                        "type": "telemetry",
                        "source_ip": b.get("source_ip"),
                        "destination_ip": b.get("destination_ip"),
                        "destination_port": b.get("destination_port"),
                        "target_filename": b.get("target_filename"),
                        "has_exec": btype == "execution",
                        "has_net": btype == "network",
                        "has_file": btype == "file",
                        "has_reg": btype == "registry",
                        "net_event_count": 1 if btype == "network" else 0,
                        "process_id": pid,
                        "parent_process_id": b.get("parent_process_id"),
                        "parent_image": b.get("parent_image"),
                        "computer": host,
                        "user": user,
                        "hosts": [host] if host else [],
                        "users": [user] if user else [],
                        # ✅ FIX: Add Burst ID with run_id
                        "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
                    }

        if current is not None:
            grouped_rows.append(current)

        return grouped_rows
    else:
        # Fallback to DF-based grouping if behaviors table is empty
        # ✅ FIX: Use event_time (we dropped utc_time in process_log_upload)
        if "event_time" in df.columns and not df.empty:
            base_tl = df.sort_values("event_time", ascending=True).copy()
        else:
            return []

        grouped_rows = []
        if not base_tl.empty:
            current = None
            for _, row in base_tl.iterrows():
                
                # ✅ ADD HARD GUARDS (Logic Fix)
                if not row.get("event_id"):
                    continue    # skip unusable events
                
                img = row.get("image") or "unknown_process"
                # ✅ FIX: Use event_time
                ut = row.get("event_time") or ""
                stage = "Unclassified"
                src_ip = row.get("source_ip")
                dst_ip = row.get("destination_ip")
                target_file = row.get("target_filename")
                host = row.get("computer")
                user = row.get("user")
                
                is_exec = row.get("event_id") == 1

                if current is None:
                    current = {
                        "start_time": ut,
                        "end_time": ut,
                        "count": 1,
                        "exec_event_count": 1 if is_exec else 0,
                        "image": img,
                        "kill_chain_stage": stage,
                        "event_ids": [str(row.get("event_id"))], # ✅ FIX 4
                        "mitre_ids": [],
                        "mitre_tactics": [],
                        "descriptions": [row.get("description")],
                        "has_correlation": False,
                        "severity": row.get("severity"),
                        "type": "telemetry",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": row.get("destination_port"),
                        "target_filename": target_file,
                        "has_exec": is_exec,
                        "has_net": row.get("event_id") == 3,
                        "has_file": row.get("event_id") in (11, 15),
                        "has_reg": row.get("event_id") in (12, 13, 14),
                        "net_event_count": 1 if row.get("event_id") == 3 else 0,
                        "computer": host,
                        "user": user,
                        "hosts": [host] if host else [],
                        "users": [user] if user else [],
                        # ✅ FIX: Add Burst ID with run_id
                        "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
                    }
                else:
                    prev_time = pd.to_datetime(
                        current["end_time"], errors="coerce", utc=True
                    )
                    this_time = pd.to_datetime(ut, errors="coerce", utc=True)
                    same_image = img == current["image"]
                    close_in_time = (
                        pd.notna(prev_time)
                        and pd.notna(this_time)
                        and (this_time - prev_time).total_seconds() <= 900
                    )
                    if same_image and close_in_time:
                        current["end_time"] = ut
                        current["count"] += 1
                        current["event_ids"].append(str(row.get("event_id"))) # ✅ FIX 4
                        if is_exec:
                            current["exec_event_count"] = current.get("exec_event_count", 0) + 1
                        
                        current["descriptions"].append(row.get("description"))
                        if src_ip:
                            current["source_ip"] = src_ip
                        if dst_ip:
                            current["destination_ip"] = dst_ip
                        if target_file:
                            current["target_filename"] = target_file
                        if is_exec:
                            current["has_exec"] = True
                        if row.get("event_id") == 3:
                            current["has_net"] = True
                            current["net_event_count"] = (
                                current.get("net_event_count", 0) + 1
                            )
                        if row.get("event_id") in (11, 15):
                            current["has_file"] = True
                        if row.get("event_id") in (12, 13, 14):
                            current["has_reg"] = True
                    else:
                        grouped_rows.append(current)
                        current = {
                            "start_time": ut,
                            "end_time": ut,
                            "count": 1,
                            "exec_event_count": 1 if is_exec else 0,
                            "image": img,
                            "kill_chain_stage": stage,
                            "event_ids": [str(row.get("event_id"))], # ✅ FIX 4
                            "mitre_ids": [],
                            "mitre_tactics": [],
                            "descriptions": [row.get("description")],
                            "has_correlation": False,
                            "severity": row.get("severity"),
                            "type": "telemetry",
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "destination_port": row.get("destination_port"),
                            "target_filename": target_file,
                            "has_exec": is_exec,
                            "has_net": row.get("event_id") == 3,
                            "has_file": row.get("event_id") in (11, 15),
                            "has_reg": row.get("event_id") in (12, 13, 14),
                            "net_event_count": 1 if row.get("event_id") == 3 else 0,
                            "computer": host,
                            "user": user,
                            "hosts": [host] if host else [],
                            "users": [user] if user else [],
                            # ✅ FIX: Add Burst ID with run_id
                            "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
                        }
            if current is not None:
                grouped_rows.append(current)
        
        return grouped_rows

def _extract_behavior_features(burst: Dict[str, Any]) -> Dict[str, Any]:
    features: Dict[str, Any] = {}

    # Identity / context
    pname = burst.get("image") or "unknown_process"
    features["process_name"] = pname
    parent_image = burst.get("parent_image")
    features["parent_process"] = (
        parent_image
        or burst.get("parent_process_id")
        or "unknown_parent"
    )
    user = (burst.get("user") or "").upper()
    features["user_type"] = "system" if "SYSTEM" in user else "interactive"

    # Time bucket
    start_ts = burst.get("start_time")
    try:
        dt = pd.to_datetime(start_ts, errors="coerce", utc=True)
        hour_bucket = int(dt.hour) if pd.notna(dt) else -1
    except Exception:
        hour_bucket = -1
    features["hour_bucket"] = hour_bucket

    # Frequency
    # Use specific execution count if available, separate from total events
    features["exec_count"] = int(burst.get("exec_event_count", burst.get("count", 0)))

    # Command behaviour – prefer real commandline
    descs = burst.get("descriptions") or []
    cmd = burst.get("commandline") or ""
    if not cmd:
        if isinstance(descs, list):
            cmd = " ".join(str(d) for d in descs)
        else:
            cmd = str(descs)
    cmd = cmd[:2000]
    lower_cmd = cmd.lower()

    # Use stable SHA256 hash instead of randomized python hash()
    features["command_hash"] = hashlib.sha256(lower_cmd.encode()).hexdigest()

    # Context-aware normalization for command length
    cmd_len = float(len(cmd))
    lp = pname.lower()
    if lp.endswith(("powershell.exe", "pwsh.exe")):
        cmd_len /= 2.0
    elif lp.endswith(("cmd.exe",)):
        cmd_len /= 1.5

    features["command_length"] = cmd_len
    features["has_encoded_flag"] = ("-enc" in lower_cmd) or ("/enc" in lower_cmd)
    features["has_download_flag"] = ("http://" in lower_cmd) or (
        "https://" in lower_cmd
    )

    # Follow‑up strength: raw signals only (no semantics)
    followup = 0
    if burst.get("has_net"):
        followup += 1
    if burst.get("has_file"):
        followup += 1
    if burst.get("has_reg"):
        followup += 1
    features["followup_events"] = followup

    # Network strength (presence vs control) – use net_event_count, not burst count
    dst_ip = burst.get("destination_ip") or ""
    net_cnt = int(burst.get("net_event_count", 0) or 0)
    features["network_strength"] = (
        2
        if dst_ip and is_external_ip(dst_ip) and net_cnt >= 3
        else 1
        if net_cnt > 0
        else 0
    )

    return features

def _compute_deviation_score(
    features: Dict[str, Any],
    baseline_entry: Optional[Dict[str, Any]],
) -> float:
    # Unknown or immature baseline: low deviation, not suspicious
    if not baseline_entry:
        return 0.15  # unknown, not anomalous

    n = int(baseline_entry.get("count_samples", 0) or 0)
    if n < 5:
        return 0.25  # very immature baseline

    # Improvement B: Per-host noise floor
    mean_val = float(baseline_entry.get("mean_exec", 0.0))
    host_noise_floor = max(5.0, mean_val)

    if float(features["exec_count"]) < host_noise_floor:
        # Dampen, do not zero
        return 0.1

    mean_exec = mean_val
    m2_exec = float(baseline_entry.get("m2_exec", 0.0))
    if n > 1:
        variance = m2_exec / max(n - 1, 1)
    else:
        variance = 0.0
    std_exec = max(variance ** 0.5, 1.0)
    freq_dev = abs(float(features["exec_count"]) - mean_exec) / std_exec
    freq_dev = min(freq_dev, 3.0)

    avg_cmd = float(baseline_entry.get("avg_cmd_len", 1.0)) or 1.0
    cmd_dev = abs(float(features["command_length"]) - avg_cmd) / avg_cmd
    cmd_dev = min(cmd_dev, 3.0)

    # Time deviation neutral for now
    time_dev = 0.0

    avg_follow = float(baseline_entry.get("avg_followup", 0.0))
    chain_dev = 1.0 if float(features["followup_events"]) >= avg_follow + 2.0 else 0.0

    # Network deviation from network_strength
    net_dev = 0.0
    ns = int(features.get("network_strength", 0) or 0)
    if ns == 2:
        net_dev = 1.0
    elif ns == 1:
        net_dev = 0.5

    raw = (
        0.30 * freq_dev
        + 0.25 * cmd_dev
        + 0.20 * chain_dev
        + 0.15 * net_dev
        + 0.10 * time_dev
    )

    # Enforce Baseline Maturity Cap inside deviation
    if not baseline_is_mature(baseline_entry):
            return min(float(min(raw / 3.0, 1.0)), 0.4)

    return float(min(raw / 3.0, 1.0))

def _update_local_baseline(
    burst: Dict[str, Any],
    features: Dict[str, Any],
    baseline_state: Dict[Tuple[str, str, str, str, int], Dict[str, Any]],
) -> None:
    # two-tier: primary (with parent), secondary (without parent)
    if int(features.get("hour_bucket", -1) or -1) < 0:
        return

    host = burst.get("computer") or "unknown_host"
    pname = features["process_name"]
    utype = features["user_type"]
    parent = features["parent_process"]
    hour = features["hour_bucket"]

    primary_key = (host, pname, utype, parent, hour)
    secondary_key = (host, pname, utype, "", hour)

    entry = baseline_state.get(primary_key)
    if not entry:
        entry = baseline_state.get(secondary_key)
        
    # Freeze baseline if mature to prevent poisoning
    if entry and int(entry.get("count_samples", 0)) > 200:
        return

    if not entry:
        baseline_state[primary_key] = {
            "count_samples": 1,
            "mean_exec": float(features["exec_count"]),
            "m2_exec": 0.0,
            "avg_cmd_len": float(features["command_length"]),
            "avg_followup": float(features["followup_events"]),
            "seen_days": 1,
        }
        return

    key_to_use = primary_key if primary_key in baseline_state else secondary_key
    entry = baseline_state[key_to_use]

    # Improvement A: Baseline Decay
    if entry.get("seen_days", 1) > 30:
        decay_factor = 0.98
        # Decay stats slightly to bias recent activity
        entry["mean_exec"] = float(entry["mean_exec"]) * decay_factor
        # Also decay count samples to allow moving average to shift faster
        entry["count_samples"] = int(entry["count_samples"] * decay_factor)
        if entry["count_samples"] < 1:
            entry["count_samples"] = 1

    n_prev = entry["count_samples"]
    n = n_prev + 1

    x = float(features["exec_count"])
    mean = float(entry.get("mean_exec", 0.0))
    m2 = float(entry.get("m2_exec", 0.0))

    delta = x - mean
    mean += delta / n
    delta2 = x - mean
    m2 += delta * delta2

    entry["mean_exec"] = mean
    entry["m2_exec"] = m2

    entry["avg_cmd_len"] = (
        entry["avg_cmd_len"] * n_prev + float(features["command_length"])
    ) / n
    entry["avg_followup"] = (
        entry["avg_followup"] * n_prev + float(features["followup_events"])
    ) / n
    entry["count_samples"] = n

def _should_learn_baseline(
    burst: Dict[str, Any],
    features: Dict[str, Any],
) -> bool:
    # Removed dead maintenance window check as requested

    # Block admin / lateral tooling from baseline
    if features["process_name"].lower() in (
        "wmic.exe", "powershell.exe", "pwsh.exe", "psexec.exe"
    ):
        return False

    # Never learn from clearly risky bursts
    if float(burst.get("risk_score", 0) or 0) >= 40.0:
        return False

    # Only learn from low-deviation activity
    if float(burst.get("deviation_score", 1.0) or 1.0) >= 0.4:
        return False

    # Never learn from encoded commands
    if features.get("has_encoded_flag"):
        return False

    # Never learn from pre-suppressed SYSTEM noise
    if burst.get("_pre_suppressed"):
        return False
        
    # Explicitly block SYSTEM noise from learning to prevent baseline drift
    if features["user_type"] == "system":
        return False

    # Only learn baseline for Execution-only behavior
    # Use normalized kill_chain_stage
    if burst.get("kill_chain_stage") != "Execution":
        return False

    # Do not learn from correlated bursts
    if burst.get("has_correlation") or burst.get("correlation_id"):
        return False

    # Do not learn persistence / injection patterns
    if burst.get("has_persistence") or burst.get("has_injection"):
        return False

    # Block strong external / beacon-like communication from learning
    if int(features.get("network_strength", 0) or 0) >= 2:
        return False

    # Do not learn from bursts that already have follow-up events
    if float(features.get("followup_events", 0) or 0) >= 2:
        return False

    return True

def _calculate_ml_deviations(
    bursts: List[Dict[str, Any]],
    baseline_state: Dict[Tuple[str, str, str, str, int], Dict[str, Any]]
) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Step 3: Extract features and calc deviation scores."""
    feature_cache = []

    for burst in bursts:
        # Data Integrity
        burst["image"] = burst.get("image") or "unknown_process"
        burst["computer"] = burst.get("computer") or "unknown_host"
        burst["start_time"] = burst.get("start_time") or datetime.datetime.utcnow().isoformat()
        
        burst.setdefault("has_exec", False)
        burst.setdefault("has_net", False)
        burst.setdefault("has_file", False)
        burst.setdefault("has_reg", False)
        burst.setdefault("has_injection", False)

        # Hardened Persistence: Registry + (Autorun Key OR Executable Target) OR File/Service Persistence
        target = (burst.get("target_filename") or "").lower()
        
        # 1. Registry Persistence logic
        reg_persistence_keys = ["currentversion\\run", "currentversion\\runonce", "services", "startup", "image file execution options"]
        is_autorun_key = any(k in target for k in reg_persistence_keys)
        is_exec_target = target.endswith((".exe", ".bat", ".ps1", ".vbs", ".dll", ".sys"))
        
        reg_persist = bool(burst.get("has_reg") and (is_autorun_key or is_exec_target))

        # 2. File/Service Persistence logic (New)
        file_persist = False
        if burst.get("has_exec") and burst.get("has_file"):
            if "system32\\tasks" in target or "services" in target:
                file_persist = True

        burst["has_persistence"] = reg_persist or file_persist

        features = _extract_behavior_features(burst)
        burst["network_strength"] = int(features.get("network_strength", 0))

        feature_cache.append((burst, features))

        host = burst.get("computer")
        pname = features["process_name"]
        utype = features["user_type"]
        parent = features["parent_process"]
        hour = int(features.get("hour_bucket", -1) or -1)

        primary_key = (host, pname, utype, parent, hour)
        secondary_key = (host, pname, utype, "", hour)

        baseline_entry = baseline_state.get(primary_key)
        if not baseline_entry:
            baseline_entry = baseline_state.get(secondary_key)

        deviation = _compute_deviation_score(features, baseline_entry)
        burst["deviation_score"] = deviation
        
        # Pre-suppression for clean SYSTEM noise
        if (
            features.get("user_type") == "system"
            and deviation < 0.3
            and int(features.get("followup_events", 0) or 0) == 0
        ):
            burst["_pre_suppressed"] = True
            burst["suppression_reason"] = "Expected SYSTEM background activity (Low Deviation)"
        else:
            burst["_pre_suppressed"] = False
            burst["suppression_reason"] = None
            
    return feature_cache

def _derive_kill_chain_from_flags(burst: Dict[str, Any]) -> str:
    has_exec = bool(burst.get("has_exec"))
    has_net = bool(burst.get("has_net"))
    has_persistence = bool(burst.get("has_persistence"))
    has_injection = bool(burst.get("has_injection"))

    exec_count = int(burst.get("count", 0) or 0)
    net_count = int(burst.get("net_event_count", 0) or 0)

    if has_injection:
        return "Privilege Escalation"

    if has_persistence:
        return "Persistence"

    # C2 dominance rules – only for external egress
    if has_net and is_external_ip(burst.get("destination_ip") or ""):
        # Strong C2 even with execution
        if net_count >= 3 and exec_count >= 5:
            return "Command and Control"
        # Pure beaconing
        if net_count >= 3 and not has_exec:
            return "Command and Control"

    # Detect Internal Lateral Movement C2
    # If high volume internal traffic, it's likely lateral movement (SMB/WMI/WinRM)
    elif has_net and not is_external_ip(burst.get("destination_ip") or "") and net_count >= 5:
        return "Command and Control"

    if has_exec:
        return "Execution"

    return "Background"

def _apply_kill_chain_logic(bursts: List[Dict[str, Any]]) -> None:
    """Step 4: Assign kill chain stages based on behavior flags."""
    for burst in bursts:
        burst.setdefault("has_exec", False)
        burst.setdefault("has_net", False)
        burst.setdefault("has_file", False)
        burst.setdefault("has_reg", False)
        burst.setdefault("has_injection", False)

        # UI Contract Fix: Canonical source is 'kill_chain_stage'
        kc = _derive_kill_chain_from_flags(burst)
        
        # Promote stage based on existing correlation if present
        # This handles the case where Correlation happened BEFORE Kill Chain logic
        if burst.get("correlation_id"):
             current_corr_stage = burst.get("kill_chain_stage")
             kc = promote_stage(current_corr_stage, kc)

        burst["kill_chain_stage"] = kc

# 🔴 UPDATE: Added run_id parameter
def _apply_correlations(bursts: List[Dict[str, Any]], corr_df: pd.DataFrame, run_id: str) -> None:
    """Step 5: Apply correlations using robust time/host/image overlap."""

    # 1. Normalize DB correlations into list of dicts
    correlations: List[Dict[str, Any]] = []
    if not corr_df.empty:
        for _, row in corr_df.iterrows():
            correlations.append(
                {
                    "corr_id": row.get("corr_id"),
                    "start_time": row.get("start_time"),
                    "end_time": row.get("end_time"),
                    "base_image": row.get("base_image"),
                    "kill_chain_stage": row.get("kill_chain_stage"),
                    "event_ids": row.get("event_ids"),
                    "computer": row.get("computer")
                }
            )

    # 2. Check each burst against existing correlations
    if bursts and correlations:
        for burst in bursts:
            burst_host = burst.get("computer")
            burst_img = burst.get("image")
            
            matched_corr = None
            
            # Robust correlation logic
            for c in correlations:
                if (c.get("computer") == burst_host and 
                    c.get("base_image") == burst_img and 
                    time_overlap(burst, c)):
                    matched_corr = c
                    break
            
            if matched_corr:
                burst["correlation_id"] = matched_corr.get("corr_id")
                corr_stage = matched_corr.get("kill_chain_stage") or "Execution"
                current_stage = burst.get("kill_chain_stage") or "Execution"
                
                # Promote stage if correlation is higher
                new_stage = promote_stage(current_stage, corr_stage)
                burst["kill_chain_stage"] = new_stage
                
                burst["correlation_score"] = 20
                burst["has_correlation"] = True

                # Ensure existing matches are marked as persisted so we don't spam writes
                burst["_corr_persisted"] = True 
            else:
                burst["correlation_id"] = None
                burst.setdefault("correlation_score", 0.0)
                burst.setdefault("has_correlation", False)

    # 3. Detect NEW Correlations (Multi-burst logic)
    correlation_index = defaultdict(list)
    for i, burst in enumerate(bursts):
        key = (
            burst.get("computer"),
            burst.get("image"),
        )
        correlation_index[key].append((i, burst))

    for key, entries in correlation_index.items():
        if len(entries) < 2:
            continue

        stages = {b.get("kill_chain_stage") for _, b in entries}

        start_times = []
        for _, b in entries:
            try:
                start_times.append(pd.to_datetime(b.get("start_time"), utc=True))
            except:
                pass
        
        campaign_age_min = 0.0
        if start_times:
            min_time = min(start_times)
            now_aware = pd.Timestamp.utcnow()
            campaign_age_min = (now_aware - min_time).total_seconds() / 60.0

        # Relaxed Persistence Threshold (10 -> 5 minutes) to catch lab activity
        if len(stages) >= 2 and campaign_age_min >= 5:
            corr_strength = 20
            if len(entries) > 5:
                corr_strength = 30

            for idx, burst in entries:
                burst["has_correlation"] = True
                current_corr = int(burst.get("correlation_score", 0.0) or 0.0)
                burst["correlation_score"] = min(max(current_corr, corr_strength), 30)
                burst["campaign_age_minutes"] = campaign_age_min

                if not burst.get("correlation_id"):
                    # ID Collision Risk -> Use Day Bucket to prevent hourly splits
                    day_bucket = datetime.datetime.utcnow().strftime("%Y%m%d")
                    burst["correlation_id"] = f"AUTO-{key[0]}-{key[1]}-{day_bucket}".lower()
                    
                # Persist ONLY if not already persisted in this run
                if not burst.get("_corr_persisted"):
                    # ✅ FIX: Debug and pass run_id
                    print("[DEBUG] about to persist campaign", run_id, burst.get("correlation_id"))
                    persist_auto_correlation(burst, run_id)
                    burst["_corr_persisted"] = True

def _compute_confidence_value(burst: Dict[str, Any], deviation_score: float, previous_state: Optional[Tuple[float, str]]) -> int:
    """Step 6a: Mathematical confidence calculation."""

    # Pre-suppressed Check
    if burst.get("_pre_suppressed"):
        burst["risk_score"] = 5
        burst["stage_cap"] = 25
        burst["classification"] = "background_activity"
        return 5

    # Use exec_event_count (actual executions) instead of total count (noise)
    executions = int(burst.get("exec_event_count", burst.get("count", 0)))

    if executions == 0:
        volume_score = 0
    elif executions < 10:
        volume_score = 5
    elif executions < 100:
        volume_score = 10
    elif executions < 1000:
        volume_score = 15
    else:
        volume_score = 20

    impact_score = 0
    if burst.get("has_exec"):
        impact_score += 10
    if burst.get("has_persistence"):
        impact_score += 25
    if burst.get("has_injection"):
        impact_score += 30

    dst_ip = burst.get("destination_ip") or ""
    is_external_net = is_external_ip(dst_ip)

    rule_score = volume_score + impact_score 

    try:
        # Update freq_log to use the new execution count variable
        freq_log = math.log10(executions + 1) if executions > 0 else 0.0
    except ValueError:
        freq_log = 0.0
    FREQ_WEIGHT = 3.0
    freq_score = freq_log * FREQ_WEIGHT
    rule_score += freq_score

    RULE_CAP = 80
    confidence = min(float(rule_score), RULE_CAP)

    stage = burst.get("kill_chain_stage") or "Execution"

    # Execution + Deviation Synergy
    ATTENTION_BONUS = 7.0
    HIGH_VOL_THRESHOLD = 200
    if (
        deviation_score >= 0.6
        and executions >= HIGH_VOL_THRESHOLD
        and stage in ("Execution", "Command and Control")
        and (burst.get("has_net") or burst.get("has_file"))
        and not burst.get("has_persistence")
        and not burst.get("has_injection")
    ):
        confidence += ATTENTION_BONUS

    if burst.get("has_persistence"):
        confidence += 15.0

    if stage == "Command and Control":
        net_events = int(burst.get("net_event_count", 0) or 0)
        if is_external_net and net_events >= 3:
            confidence += 25.0
        elif is_external_net:
            confidence += 10.0

    if burst.get("has_injection"):
        confidence += 25.0
        
    # Correlation Score Logic Update
    # Correlation is a classification accelerator, not raw confidence.
    # We do NOT add arbitrary points anymore.
    if burst.get("has_correlation") and confidence < 40.0:
        confidence = 40.0

    # Deviation Gating (Trust Gate)
    if deviation_score < 0.3:
        deviation_cap = 25.0
    elif deviation_score < 0.6:
        deviation_cap = 40.0
    elif deviation_score < 0.8:
        deviation_cap = 70.0
    else:
        deviation_cap = 100.0

    # Stage Cap
    if stage in ("Privilege Escalation", "Actions on Objectives"):
        stage_cap = 100
    elif stage in ("Command and Control", "Persistence"):
        stage_cap = 80
    elif stage == "Execution":
        stage_cap = 60
    else:
        stage_cap = 40

    confidence = min(confidence, float(stage_cap))
    confidence = min(confidence, deviation_cap)

    # Smoothing
    if previous_state is not None:
        prev_conf, prev_stage = previous_state
        if prev_stage == stage:
             confidence = 0.7 * float(prev_conf) + 0.3 * confidence

    confidence = max(0.0, min(confidence, 100.0))
    burst["risk_score"] = int(round(confidence))
    burst["stage_cap"] = stage_cap

    # Classification
    is_attack_candidate = (
        confidence >= 40.0
        or burst.get("has_persistence")
        or burst.get("has_injection")
        or (
            stage in ("Command and Control", "Actions on Objectives")
            and confidence >= 40.0
        )
        or burst.get("has_correlation")
    )
    burst["classification"] = (
        "attack_candidate" if is_attack_candidate else "background_activity"
    )

    return burst["risk_score"]

def _calculate_confidence_and_severity(bursts: List[Dict[str, Any]], feature_cache: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> None:
    """Step 6: Compute risk, determine severity (decoupled), and attach reasons."""
    prev_conf_map: Dict[Tuple[str, str, str, str, int], Tuple[float, str]] = {}

    # We must match bursts to their cached features index-wise
    # Assuming feature_cache is ordered same as bursts (it is in _calculate_ml_deviations)

    for i, burst in enumerate(bursts):
        _, features = feature_cache[i] # unpack (burst_ref, features)
        
        host = burst.get("computer") or "unknown_host"
        key = (
            host,
            features["process_name"],
            features["user_type"],
            features["parent_process"],
            features["parent_process"],
            int(features.get("hour_bucket", -1)),
        )
        prev_state = prev_conf_map.get(key)
        
        score = _compute_confidence_value(burst, float(burst.get("deviation_score", 0.0) or 0.0), prev_state)
        
        # Strictly Decouple Severity from Confidence
        kc = burst.get("kill_chain_stage", "Background")
        r_score = burst.get("risk_score", 0)
        
        # Severity is IMPACT. Confidence is PROBABILITY.
        if kc in ("Persistence", "Command and Control", "Actions on Objectives", "Privilege Escalation"):
            severity = "high"
        # Blast Radius Check (Multi-host = High Severity)
        elif len(burst.get("hosts", [])) > 1:
            severity = "high"
        elif r_score >= 60:
            # High confidence execution is medium severity (unless it's one of the above)
            severity = "medium"
        else:
            severity = "low"
            
        burst["severity"] = severity
        
        # Analyst Override Check (Architecture support)
        # If an override field exists (e.g. from an upstream process), honor it
        if burst.get("analyst_verdict") and burst.get("analyst_verdict") != "Unclassified":
            burst["confidence_source"] = "Analyst Override"
            if burst.get("analyst_verdict") == "Likely Malicious":
                burst["risk_score"] = 100
                burst["severity"] = "high"
        else:
            burst["confidence_source"] = "AI/ML Engine"
        
        current_stage = kc
        prev_conf_map[key] = (float(score), current_stage)
        
        # Attach reasons
        confidence_reasons = []

        dev = burst.get("deviation_score", None)
        DEV_LOW = 0.3
        DEV_HIGH = 0.6

        if dev is not None:
            if dev < DEV_LOW:
                confidence_reasons.append("Low deviation from baseline")
            elif dev > DEV_HIGH:
                confidence_reasons.append("Significant deviation from baseline")

        stage = burst.get("kill_chain_stage") or "Background"
        if stage == "Execution":
            confidence_reasons.append("Execution-only behavior")
        elif stage in ("Privilege Escalation", "Command and Control", "Actions on Objectives"):
            confidence_reasons.append(f"Advanced kill-chain stage: {stage}")

        # Preserve any existing reasons you had
        existing = burst.get("confidence_reasons") or []
        burst["confidence_reasons"] = existing + confidence_reasons
        burst["ai_context"] = burst["confidence_reasons"][0] if burst["confidence_reasons"] else None

def _update_baselines(feature_cache: List[Tuple[Dict[str, Any], Dict[str, Any]]], baseline_state: Dict) -> None:
    """Step 7: Learning Phase."""
    for burst, features in feature_cache:
        if _should_learn_baseline(burst, features):
            _update_local_baseline(burst, features, baseline_state)

# -------------------------------------------------------------------
# Baseline Context Gating Logic
# -------------------------------------------------------------------
def _baseline_generate_soc_reason(b: Dict[str, Any]) -> str:
    return "Stable baseline execution (non-alerting)"

# 🔴 CHANGE 1: Accept run_id parameter
def run_full_analysis(run_id: str) -> Dict[str, Any]:
    """
    Run the full SOC analysis once using modular steps.
    Returns a dict with the SAME keys index.html expects.
    """
    
    # 🔥 STEP 4: SNAPSHOT CACHE CHECK REMOVED
    
    # 🔴 ADD THIS AT THE VERY TOP (FIRST 5 LINES)
    print("🔥 run_full_analysis CALLED with run_id =", run_id)
    # We do NOT mutate raw events here anymore; we mutate the UI layer below.
    
    # ============================================================
    # 🔒 SAFE INITIALIZATION (MANDATORY)
    # ============================================================
    # --- SAFE DEFAULT INITIALIZATION (MANDATORY) ---
    evidence_state = {}

    # --- Kill chain ---
    kill_chain_summary = []
    kc_severity = {}
    highest_kill_chain = None
    
    # --- MITRE ---
    mitre_summary = []

    # --- Correlation / campaigns ---
    correlation_campaigns = []
    correlations = []
    correlations_detail = []
    correlation_hunts = []
    correlation_score = 0

    # --- Events & stats ---
    top_events = []
    interesting = []
    recent = []
    events_per_hour = []
    events_by_severity = {"high": 0, "medium": 0, "low": 0}
    
    # --- LOLBins (MANDATORY FIX) ---
    lolbins_summary = []
    
    # --- Baseline ---
    baseline_execution_context = []
    top_baseline_events = []

    # --- Bursts ---
    burst_aggregates = []
    top_dangerous_bursts = []
    timeline = []

    # --- Confidence model ---
    attack_conf_score = 0
    attack_conf_level = "Low"
    attack_conf_cap = None
    attack_conf_cap_reason = None
    attack_conf_basis = []
    dominant_burst = None
    confidence_trend = []

    # --- Analyst guidance ---
    analyst_verdict = None
    analyst_action = None
    action_priority = None
    action_reason = None
    response_tasks = []

    # --- Incident ---
    incident = None

    # ✅ FIX 5: REMOVE FAKE STABILITY (Enable DEV_MODE to clear baseline)
    # This prevents the dashboard from 'settling' into a state where new anomalies are ignored.
    DEV_MODE = False
    
    if DEV_MODE:
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='behavior_baseline'
            """)
            if cur.fetchone():
                cur.execute("DELETE FROM behavior_baseline")
                conn.commit()
                print("[DEV] Behavior baseline reset")
        except Exception as e:
            print(f"[DEV] Failed to reset baseline: {e}")
        finally:
            conn.close()

    # FIX 3: Campaign Lifecycle Update (Close old campaigns)
    update_campaign_status_lifecycle()

    # 1. Load Data
    # 🔴 UPDATED: Pass run_id to ALL loaders
    df = load_events(run_id)

    # 🔴 CHANGE 2: Compute total_events from that df right after loading
    total_events = int(len(df)) if not df.empty else 0
    if not df.empty:
        df = df.rename(columns={
            "pid": "process_id",
            "ppid": "parent_process_id",
            "command_line": "command_line",
        })

        if "event_time" not in df.columns:
            if "utc_time" in df.columns:
                df["event_time"] = pd.to_datetime(df["utc_time"], errors="coerce", utc=True)
            else:
                df["event_time"] = pd.NaT
        else:
            df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce", utc=True)

        df = df.dropna(subset=["event_time"])

    # -----------------------------------------------------------
    # FIX: Deduplicate columns immediately to prevent downstream crashes
    # -----------------------------------------------------------
    # ✅ FIX: Pass run_id here!
    detections_df = load_detections(run_id)
    # ✅ MANDATORY FIX 1: Deduplicate columns immediately for detections_df
    detections_df = detections_df.loc[:, ~detections_df.columns.duplicated()]

    # ✅ FIX: Pass run_id here!
    corr_df = load_correlations(run_id)
    
    # ✅ FIX: Pass run_id so we only see campaigns for THIS file
    campaigns_df = load_correlation_campaigns(run_id) 
    
    # ✅ FIX: Pass run_id here!
    beh_df = load_behaviors(run_id)
    
    baseline_state = load_behavior_baseline()

    # FIX: Define correlations safely for UI context even if empty
    correlations = corr_df.to_dict(orient="records") if not corr_df.empty else []

    # --- Detection Normalization Layer ---
    if not detections_df.empty:
        norm = detections_df.copy()

        # Date parsing (Safe now because of deduplication)
        # Note: Loaders already renamed event_time -> utc_time, so we use utc_time here
        norm["_parsed_time_det"] = pd.to_datetime(
            norm["utc_time"], errors="coerce", utc=True
        )

        # FIX: Ensure scalar Series columns for aggregation to prevent AttributeError
        for col in ["_parsed_time_det", "event_id", "parent_image"]:
            if col in norm.columns and isinstance(norm[col], pd.DataFrame):
                norm[col] = norm[col].iloc[:, 0]

        grouped_norm = (
            norm.groupby(["rule_id", "image", "mitre_id"])
            .agg(
                first_seen=("_parsed_time_det", "min"),
                last_seen=("_parsed_time_det", "max"),
                count=("event_id", "size"),
                unique_parents=("parent_image", "nunique"),
            )
            .reset_index()
        )
        normalized_detections = grouped_norm
    else:
        normalized_detections = pd.DataFrame(
            columns=[
                "rule_id", "image", "mitre_id", "first_seen",
                "last_seen", "count", "unique_parents",
            ]
        )

    # 2. Build Bursts
    # ✅ FIX: Pass run_id to generate unique burst IDs
    grouped_rows = _build_bursts(df, beh_df, run_id)

    # 3. ML Deviation (Pass 1)
    feature_cache = _calculate_ml_deviations(grouped_rows, baseline_state)

    # NEW: Ensure each burst has a simple deviation_score scalar for UI/logic
    for burst, features in feature_cache:
        dev = features.get("deviation_score")
        if dev is not None:
            try:
                burst["deviation_score"] = float(dev)
            except Exception:
                pass

    # Change Execution Order (MANDATORY)
    # Clear persistence flags before run to ensure current logic applies
    for burst in grouped_rows:
        burst.pop("_corr_persisted", None)

    # 4. Correlation Logic (Moved UP)
    # Correlation must happen before kill-chain logic so kill-chain can be promoted
    
    # ✅ FIX: Pass run_id
    _apply_correlations(grouped_rows, corr_df, run_id)

    # 5. Kill Chain Logic (Derived from correlation or local evidence)
    _apply_kill_chain_logic(grouped_rows)

    # 6. Confidence & Severity (Calculated LAST)
    _calculate_confidence_and_severity(grouped_rows, feature_cache)

    # 7. Learning (Fixed Freeze)
    _update_baselines(feature_cache, baseline_state)
    
    # ✅ Persist updated baseline state after learning
    persist_behavior_baseline(baseline_state)

    # --- Baseline summary for UI ---
    baseline_execution_context = []
    top_dangerous_bursts = []
    if not df.empty:
        df_base = df.copy()

        # Clean image + computer, drop garbage rows
        df_base["image"] = df_base["image"].astype(str).str.strip()
        if "computer" not in df_base.columns:
            df_base["computer"] = None

        df_base = df_base[
            df_base["image"].notna()
            & (df_base["image"] != "")
            & (df_base["image"].str.lower() != "unknown process")
        ]

        if not df_base.empty:
            grouped = (
                df_base.groupby(["image", "computer"], dropna=False)
                        .agg(
                           first_seen=("event_time", "min"),
                           last_seen=("event_time", "max"),
                           exec_count=("event_id", "size"),
                        )
                        .reset_index()
            )

            # Derive execution rate, compact time labels, baseline state, parent context
            baseline_rows = []
            for _, r in grouped.iterrows():
                start = r["first_seen"]
                end = r["last_seen"]
                duration = end - start
                seconds = max(duration.total_seconds(), 60.0)
                minutes = seconds / 60.0

                exec_count = int(r["exec_count"])
                exec_rate_per_min = exec_count / minutes

                total_minutes = int(duration.total_seconds() // 60)
                hours = total_minutes // 60
                mins = total_minutes % 60
                if hours:
                    duration_label = f"{hours}h {mins}m"
                else:
                    duration_label = f"{mins}m"

                start_label = start.strftime("%H:%M")
                end_label = end.strftime("%H:%M")

                # Simple 3‑level baseline state based ONLY on this run
                if exec_rate_per_min < 1:
                    baseline_state_label = "Low activity in this run"
                elif exec_rate_per_min < 10:
                    baseline_state_label = "Bursting in this run"
                else:
                    baseline_state_label = "Heavy activity in this run"

                # Dominant parent for this (image, computer)
                parent_image = None
                subset = df_base[
                    (df_base["image"] == r["image"]) &
                    (df_base["computer"] == r["computer"])
                ]
                if "parent_image" in subset.columns and not subset.empty:
                    pc = (
                        subset.groupby("parent_image")
                              .size()
                              .reset_index(name="count")
                              .sort_values("count", ascending=False)
                    )
                    if not pc.empty:
                        parent_image = pc["parent_image"].iloc[0]

                # Look up long-term baseline entry if present
                host = r.get("computer") or "unknown_host"
                key = (host, r["image"])
                baseline_entry = baseline_state.get(key) if isinstance(baseline_state, dict) else None
                baseline_exec_rate = float(baseline_entry.get("avg_exec_rate", 0.0)) if baseline_entry else 0.0

                if baseline_exec_rate > 0:
                    freq_ratio = exec_rate_per_min / baseline_exec_rate
                else:
                    freq_ratio = None

                if freq_ratio is None:
                    deviation_label = "No historical baseline"
                elif freq_ratio < 1.5:
                    deviation_label = "Within normal host baseline"
                elif freq_ratio < 3.0:
                    deviation_label = "Elevated vs host baseline"
                else:
                    deviation_label = "Strongly elevated vs host baseline"

                baseline_rows.append({
                    "image": r["image"],
                    "computer": host,
                    "first_seen": start.isoformat(),
                    "last_seen": end.isoformat(),
                    "start_label": start_label,
                    "end_label": end_label,
                    "duration_label": duration_label,
                    "exec_count": exec_count,
                    "exec_rate_per_min": round(exec_rate_per_min, 1),
                    "baseline_state": baseline_state_label,
                    "parent_image": parent_image,
                    "baseline_deviation": deviation_label,  # NEW
                    "why_non_alerting": [
                        deviation_label,
                        "No persistence indicators in this run",
                        "No external network activity tied to this process in this run",
                    ],
                })

            # Sort by state (least stable first), then newest, then volume
            state_order = {"Unusual but Learned": 0, "Expected Burst": 1, "Stable": 2}
            baseline_rows.sort(
                key=lambda b: (
                    state_order.get(b["baseline_state"], 2),
                    b["first_seen"],
                    -b["exec_count"],
                )
            )

            # LIMIT: only top 10 rows
            baseline_rows = baseline_rows[:10]

            baseline_execution_context = baseline_rows
            top_dangerous_bursts = baseline_rows

    # NEW: mark bursts that match a mature, low-variance baseline as likely benign
    for burst in grouped_rows:
        # features key should match whatever you use in baseline (e.g., host, image, user type, parent, hour)
        host = burst.get("computer") or "unknown_host"
        image = burst.get("image") or "unknown_process"
        user = (burst.get("user") or "").upper()
        parent = burst.get("parent_image") or ""
        hour = -1
        try:
            start_ts = burst.get("start_time")
            dt = pd.to_datetime(start_ts, errors="coerce", utc=True)
            if pd.notna(dt):
                hour = int(dt.hour)
        except:
            pass

        # Simplified key – adjust to your actual baseline key schema
        # Baseline key is: (computer, process_name, user_type, parent_process, hour_bucket)
        key = (host, image, "system" if "SYSTEM" in user else "interactive", parent, hour)

        entry = baseline_state.get(key)
        if not entry:
            continue

        # Heuristic: many samples and low variance → mature benign pattern
        count_samples = int(entry.get("count_samples", entry.get("count", 0)) or 0)
        var_exec = float(entry.get("var_exec", entry.get("var_exec", 0.0)) or 0.0)

        if count_samples >= 50 and var_exec < 0.5:
            # Mark for later suppression in the final loop
            burst["_baseline_benign_hint"] = True

    # ✅ FIX: Force persistence loop per user instruction
    print(f"[DEBUG] forcing persist_auto_correlation loop for {len(grouped_rows)} bursts")
    for burst in grouped_rows:
        if burst.get("correlation_id"):
            print(f"[DEBUG] calling persist_auto_correlation for {run_id} {burst.get('correlation_id')}")
            persist_auto_correlation(burst, run_id)

    # 8. Final Cleanup (Suppression Check & Normalization)
    for burst in grouped_rows:

        # Analyst override: if an analyst_verdict was stored on this burst, respect it
        if burst.get("analyst_verdict") and burst.get("analyst_verdict") != "Unclassified":
            burst["confidence_source"] = "Analyst Override"
            verdict = burst["analyst_verdict"]
            if verdict == "Likely Malicious":
                burst["risk_score"] = 100
                burst["severity"] = "high"
            elif verdict == "Benign":
                burst["risk_score"] = min(burst.get("risk_score", 0) or 0, 10)
                burst.setdefault("suppression_reason", "Analyst marked as benign")
            # Skip automatic suppression changes for overridden bursts
            continue

        # ✅ NORMALIZE TYPES (MANDATORY FIX)
        # Convert NumPy/Pandas Int64 to Python int for JSON serialization
        if "risk_score" in burst:
            burst["risk_score"] = int(burst["risk_score"])
        if "stage_cap" in burst:
            burst["stage_cap"] = int(burst["stage_cap"])


        # Final Safety Net for Suppression
        if not burst.get("_pre_suppressed"):
            user = (burst.get("user") or "").upper()
            dev = float(burst.get("deviation_score", 0.0) or 0.0)
            dst_ip = burst.get("destination_ip") or ""
            is_external_net = is_external_ip(dst_ip)
            has_followup = bool(
                burst.get("has_persistence")
                or burst.get("has_injection")
                or is_external_net
            )
            
            image = (burst.get("image") or "").lower()
            parent = (burst.get("parent_image") or "").lower()

            # NEW: known benign system/service images
            known_benign_images = {
                "services.exe",
                "wininit.exe",
                "winlogon.exe",
                "lsass.exe",
                "csrss.exe",
                "svchost.exe",
                "spoolsv.exe",
                "explorer.exe",
            }

            # NEW: known benign parent processes (EDR/AV/management)
            known_benign_parents = {
                "splunkd.exe",
                "osqueryd.exe",
                "senseir.exe",
                "crowdstrike.exe",
                "carbonblack.exe",
            }

            baseline_benign = bool(burst.get("_baseline_benign_hint"))

            # Rule 1: SYSTEM-owned, low deviation, no follow-up → aggressively clamp
            if "SYSTEM" in user and dev < 0.3 and not has_followup:
                burst["risk_score"] = min(burst.get("risk_score", 0) or 0, 15)
                burst["classification"] = "background_activity"
                burst.setdefault("suppression_reason", "SYSTEM low-deviation background activity")

            # Rule 2: known benign image with low deviation and no late-stage kill chain
            # or baseline explicitly marks it as mature benign
            elif (image in known_benign_images or baseline_benign) and dev < 0.4:
                stage = burst.get("kill_chain_stage") or "Background"
                if stage in ("Background", "Execution"):
                    burst["risk_score"] = min(burst.get("risk_score", 0) or 0, 20)
                    burst.setdefault("suppression_reason", "Known/baselined benign image with low deviation")

            # Rule 3: known benign parent and no external network
            elif parent in known_benign_parents and not is_external_net and dev < 0.5:
                burst["risk_score"] = min(burst.get("risk_score", 0) or 0, 25)
                burst.setdefault("suppression_reason", "Child of known benign parent with low deviation")

        # UI Field Normalization & Contract Stabilization
        burst.setdefault("confidence_reasons", [])
        burst.setdefault("suppression_reason", None)
        burst.setdefault("confidence_source", "AI/ML Engine")
        burst.setdefault("correlation_score", 0)
        burst.setdefault("campaign_age_minutes", 0.0)
        
        # UI Contract Violation (Clean & Safe)
        # Force single source of truth at the output layer
        kc = burst.get("kill_chain_stage")
        burst["final_kill_chain"] = kc
        # Clean up legacy/redundant keys to prevent UI ambiguity
        if "inferred_kill_chain" in burst:
             del burst["inferred_kill_chain"]

    # --- Context Building for UI (Legacy Logic kept mostly as-is for compatibility) ---
    # We already computed total_events at the top, so we do not recompute len(df) here
    
    # ✅ FIX 3: Fix severity counting (fillna)
    if "severity" in df.columns:
        df["severity"] = df["severity"].fillna("low")
        sev_counts = {
            str(k): int(v) 
            for k, v in df["severity"].str.lower().value_counts().to_dict().items()
        }
        high_count = (df["severity"].str.lower() == "high").sum()
        medium_count = (df["severity"].str.lower() == "medium").sum()
        low_count = (df["severity"].str.lower() == "low").sum()
    else:
        sev_counts = {}
        high_count = 0
        medium_count = 0
        low_count = 0
        
    events_by_severity = sev_counts
    detections_count = len(detections_df)

    # --- FIX: Define top_events (User Option 1) ---
    if df is not None and not df.empty:
        # Robust handle for Pandas version diffs in reset_index()
        _te = df["event_id"].value_counts().head(10).reset_index()
        _te.columns = ["event_id", "count"]
        top_events = _te.to_dict(orient="records")
    else:
        top_events = []

    suspicious_images = [
        "cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe",
        "rundll32.exe", "regsvr32.exe", "mshta.exe",
    ]

    if not df.empty and "image" in df.columns:
        interesting_df = (
            df[
                df["image"].notna()
                & df["image"]
                .str.lower()
                .str.contains("|".join(x.lower() for x in suspicious_images), na=False)
            ]
            .sort_values("utc_time", ascending=False)
            .head(100)
        )
    else:
        interesting_df = df.iloc[0:0]

    recent_df = (
        df.sort_values("utc_time", ascending=False).head(50)
        if "utc_time" in df.columns
        else df
    )

    # Detections table logic
    if not detections_df.empty and "severity" in detections_df.columns:
        det_copy = detections_df.copy()
        sev_norm = det_copy["severity"].fillna("unknown").str.lower()
        impact: List[str] = []
        for s in sev_norm:
            if s == "high":
                impact.append("+10")
            elif s == "medium":
                impact.append("+5")
            elif s == "low":
                impact.append("+2")
            else:
                impact.append("+0")
        det_copy["confidence_impact"] = impact
    else:
        det_copy = detections_df.copy()
        det_copy["confidence_impact"] = "+0"

    detections = (
        det_copy.sort_values("utc_time", ascending=False).head(50)
        if "utc_time" in det_copy.columns
        else det_copy
    )

    # --- AGGREGATION FIX 2: Group bursts by image + context + time bucket (FIX 2) ---
    agg = defaultdict(list)
    for i, b in enumerate(grouped_rows):
        # 🔴 CHANGE 4: Add run_id to burst aggregation key
        key = (
            b["image"],
            b.get("computer"),
            run_id,
            (b.get("start_time") or "")[:13] 
        )
        agg[key].append((i, b))

    burst_aggregates = []
    # Updated loop to unpack the new key structure
    for (image, computer, rid, time_bucket), items in agg.items():
        # FIX 2: Stable Burst ID from the representative item for UI linking
        # ✅ CHANGE 5: Use ID from first burst
        burst_id = items[0][1].get("burst_id")

        # Collect flattened event IDs for the UI to list
        # NEW: Deduplicate event IDs logic
        raw_ids_set = set()
        for _, b in items:
            eids = b.get("event_ids", [])
            if isinstance(eids, list):
                for e in eids:
                    # Filter out None or 'None' strings
                    if e and str(e).lower() != 'none':
                        raw_ids_set.add(str(e))
            elif eids:
                if str(eids).lower() != 'none':
                    raw_ids_set.add(str(eids))
        
        # Sort numerically for cleaner display (e.g., 1, 3, 11)
        combined_event_ids = sorted(list(raw_ids_set), key=lambda x: int(x) if x.isdigit() else x)
        
        # Get Stage Cap from the highest scoring burst
        max_risk_burst = max(items, key=lambda x: x[1].get("risk_score", 0))[1]
        stage_cap_val = max_risk_burst.get("stage_cap", 100)
        
        indices_list = [i for i, _ in items]

        # FIX: Normalize schema for UI compatibility & Evidence Calculation
        burst_aggregates.append({
            "burst_id": burst_id,  # Added this field
            "image": image,
            "kill_chain_stage": max(b["kill_chain_stage"] for _, b in items),
            "total_count": sum(b["count"] for _, b in items),
            "peak_score": max(b["risk_score"] for _, b in items),
            "confidence_reasons": items[0][1].get("confidence_reasons", []),
            
            # 🔥 REQUIRED BY UI (Fixed)
            "timeline_indices": indices_list,
            "event_ids": combined_event_ids,
            "stage_cap": stage_cap_val,
            
            # Added missing UI fields:
            "burst_count": len(items),
            "_pre_suppressed": items[0][1].get("_pre_suppressed", False),
            "ai_context": items[0][1].get("ai_context"),
            # FIX: Aggregate correlation status for the group so the filter can see it
            "has_correlation": any(b.get("has_correlation") for _, b in items),
            # FIX: Aggregate event type counts for precise evidence string
            "exec_sum": sum(b.get("exec_event_count", 0) for _, b in items),
            "net_sum": sum(b.get("net_event_count", 0) for _, b in items),
            "file_sum": sum(1 for _, b in items if b.get("has_file")),
            "reg_sum": sum(1 for _, b in items if b.get("has_reg")),
        })

    # Sort aggregates by peak score for general usage
    burst_aggregates.sort(key=lambda x: x["peak_score"], reverse=True)

    # --- SCENARIO-LEVEL ATTACK CONFIDENCE (SOC-style) ---
    attack_conf_score = 0
    attack_conf_basis = []

    # 1) base on max detection confidence_score (if present)
    max_det_conf = 0
    if not detections_df.empty and "confidence_score" in detections_df.columns:
        try:
            max_det_conf = int(detections_df["confidence_score"].fillna(0).astype(int).max())
        except Exception:
            max_det_conf = 0

    if max_det_conf >= 80:
        attack_conf_score += 40
        attack_conf_basis.append("High-confidence detection rules triggered")
    elif max_det_conf >= 50:
        attack_conf_score += 25
        attack_conf_basis.append("Medium-confidence detection rules triggered")
    elif max_det_conf > 0:
        attack_conf_score += 10
        attack_conf_basis.append("Low-confidence detection rules triggered")

    # 2) distinct MITRE tactics in this run
    distinct_tactics = set()
    if not detections_df.empty and "mitre_tactic" in detections_df.columns:
        distinct_tactics = {
            str(t).strip()
            for t in detections_df["mitre_tactic"].dropna()
            if str(t).strip()
        }
        n_tactics = len(distinct_tactics)
        if n_tactics >= 3:
            attack_conf_score += 25
            attack_conf_basis.append(f"Multiple MITRE tactics observed ({n_tactics})")
        elif n_tactics >= 1:
            attack_conf_score += 10
            attack_conf_basis.append("At least one MITRE tactic observed")

    # 3) highest kill-chain stage from bursts
    stage_order = KILL_CHAIN_ORDER
    highest_kill_chain: Optional[str] = None
    if grouped_rows:
        stages = [
            b.get("kill_chain_stage")
            for b in grouped_rows
            if b.get("kill_chain_stage") in stage_order
            and (int(b.get("risk_score", 0) or 0) >= 40 or b.get("has_correlation"))
        ]
        if stages:
            highest_kill_chain = sorted(stages, key=lambda s: stage_order.index(s))[-1]

    if highest_kill_chain in ("Command and Control", "Actions on Objectives"):
        attack_conf_score += 25
        attack_conf_basis.append(f"Kill-chain progressed to {highest_kill_chain}")
    elif highest_kill_chain:
        attack_conf_score += 10
        attack_conf_basis.append(f"Kill-chain evidence up to {highest_kill_chain}")

    # 4) correlated multi-stage activity
    if correlations:
        attack_conf_score += 15
        attack_conf_basis.append("Multi-stage correlation present in this run")

    # 5) also consider max burst peak_score as a signal, but bounded
    max_burst_risk = 0
    if burst_aggregates:
        max_burst_risk = max(int(b["peak_score"] or 0) for b in burst_aggregates)
        attack_conf_score += min(20, max_burst_risk // 5)
        attack_conf_basis.append(f"Highest burst risk score {max_burst_risk}")

    attack_conf_score = min(100, attack_conf_score)

    if attack_conf_score >= 80:
        attack_conf_level = "High"
    elif attack_conf_score >= 50:
        attack_conf_level = "Medium"
    elif attack_conf_score > 0:
        attack_conf_level = "Low"
    else:
        attack_conf_level = "None"

    # Highest kill chain logic
    # (Redundant calculation above used for scoring, keeping for downstream variable use consistency)
    
    if highest_kill_chain == "Actions on Objectives":
        attack_conf_cap = 100
    elif highest_kill_chain == "Command and Control":
        attack_conf_cap = 80
    elif highest_kill_chain == "Persistence":
        attack_conf_cap = 70
    elif highest_kill_chain == "Exploitation": # If present in future logic
        attack_conf_cap = 60
    else:
        attack_conf_cap = 50 if attack_conf_score > 0 else None

    # Apply cap logic
    raw_max_score = attack_conf_score
    if attack_conf_cap is not None:
        attack_conf_score = min(attack_conf_score, attack_conf_cap)

    if attack_conf_cap is not None and attack_conf_score < raw_max_score:
        attack_conf_basis.append(
            f"Overall confidence capped at {attack_conf_cap} due to "
            f"absence of later-stage kill-chain evidence."
        )
    elif highest_kill_chain:
        attack_conf_basis.append(
            f"Confidence is limited by the highest observed kill-chain stage ({highest_kill_chain})."
        )
    elif attack_conf_score > 0 and not attack_conf_basis:
        attack_conf_basis.append(
            "Confidence derived from execution/behavior indicators without confirmed later-stage activity."
        )

    confidence_trend = [int(b.get("risk_score", 0) or 0) for b in grouped_rows]

    # --- FIX: Define correlation_hunts safely for UI ---
    if "correlations" in locals() and correlations:
        correlation_hunts = [
            {
                "id": c.get("corr_id"),
                "description": c.get("description", "Correlation detected"),
                "severity": c.get("severity", "medium"),
            }
            for c in correlations
        ]
    else:
        correlation_hunts = []

    # --- FIX: Define correlation_score safely ---
    if "correlations" in locals() and correlations:
        # Simple heuristic: number of correlations * severity weight
        severity_weight = {
            "low": 1,
            "medium": 2,
            "high": 3
        }

        correlation_score = sum(
            severity_weight.get(
                (c.get("severity") or "low").lower(), 
                1
            )
            for c in correlations
        )
    else:
        correlation_score = 0

    # --- FIX: Define interesting from interesting_df ---
    if "interesting_df" in locals() and interesting_df is not None and not interesting_df.empty:
        # ✅ MANDATORY FIX 1: Deduplicate columns for interesting_df
        interesting_df = interesting_df.loc[:, ~interesting_df.columns.duplicated()]
        interesting = interesting_df.to_dict(orient="records")
    else:
        interesting = []

    if "recent_df" in locals() and not recent_df.empty:
        # ✅ MANDATORY FIX 1: Deduplicate columns for recent_df
        recent_df = recent_df.loc[:, ~recent_df.columns.duplicated()]
        recent = recent_df.to_dict(orient="records")
    else:
        recent = []

    # 2. Group and collapse (Backend summary logic)
    # This logic has been removed as per instructions because baseline_execution_context
    # is now calculated immediately after df loading.
    
    # We still need this for UI reporting
    top_baseline_events = baseline_execution_context
    
    # ✅ FIX: Added counting logic
    baseline_noise_count = len(baseline_execution_context)

    # -------------------------------------------------------------------------
    # DEBUG Logic for baseline
    # -------------------------------------------------------------------------
    print("[DEBUG] baseline_execution_context len:", len(baseline_execution_context))
    print("[DEBUG] baseline_noise_count:", baseline_noise_count)
        
    # 🔧 FIX ADDED HERE: Initialize lolbin_stats dictionary
    lolbin_stats = {}

    if not interesting_df.empty and "image" in interesting_df.columns:
        normal_parents = {"services.exe", "wininit.exe", "winlogon.exe", "splunkd.exe"}
        normal_parents_l = {p.lower() for p in normal_parents}
        for _, row in interesting_df.iterrows():
            img = row.get("image") or "unknown_process"
            cmd = row.get("commandline") or row.get("command_line") or ""
            parent = (row.get("parent_image") or "").strip()

            s = lolbin_stats.setdefault(
                img,
                {
                    "image": img,
                    "executions": 0,
                    "unique_commands": set(),
                    "abnormal_parents": set(),
                },
            )
            s["executions"] += 1
            if cmd:
                s["unique_commands"].add(cmd)
            if parent and parent.lower() not in normal_parents_l:
                s["abnormal_parents"].add(parent)
                
    # --- LOLBins Summary Generation ---
    if lolbin_stats:
        lolbins_summary = []
        for img, s in lolbin_stats.items():
            execs = s["executions"]
            uniq = len(s["unique_commands"])
            abnormal = len(s["abnormal_parents"])

            if execs > 100 and uniq <= 3 and abnormal == 0:
                verdict = "likely benign (service activity)"
            elif abnormal > 0 or uniq > 3:
                verdict = "suspicious"
            else:
                verdict = "inconclusive"

            lolbins_summary.append(
                {
                    "image": img,
                    "executions": execs,
                    "unique_command_lines": uniq,
                    "abnormal_parents": abnormal,
                    "verdict": verdict,
                }
            )

        lolbins_summary.sort(
            key=lambda r: (r["abnormal_parents"], r["executions"]), reverse=True
        )
        lolbins_summary = lolbins_summary[:10]

    # ✅ MANDATORY FIX 1: Deduplicate columns for detections (extracted from detections_df)
    detections = detections.loc[:, ~detections.columns.duplicated()]

    # --- MITRE Summary Logic ---
    mitre_summary: List[Dict[str, Any]] = []
    if not detections_df.empty and "mitre_id" in detections_df.columns:
        tmp = (
            detections_df
            .fillna({"mitre_tactic": "Unknown", "mitre_id": "Unmapped"})
            .groupby(["mitre_tactic", "mitre_id"])
            .size()
            .reset_index(name="count")
        )
        for _, row in tmp.iterrows():
            mitre_summary.append(
                {
                    "mitre_tactic": row["mitre_tactic"],
                    "mitre_id": row["mitre_id"],
                    "count": int(row["count"]),
                }
            )
    
    print("[DEBUG] non-null mitre_ids:", detections_df["mitre_id"].notna().sum() if not detections_df.empty and "mitre_id" in detections_df.columns else 0)
    print("[DEBUG] mitre_summary len:", len(mitre_summary))

    # -------------------------------------------------------------------------
    # ✅ FIX: Construct Incident Object & Alert Status for UI Header
    # -------------------------------------------------------------------------
    is_alertable = bool(incident) or (
        attack_conf_score >= 40 
        and (correlation_score > 0 or highest_kill_chain not in (None, "Background"))
    )
    
    if is_alertable and incident is None:
        incident = {
            "incident_id": f"INC-{run_id[:8]}",
            "status": "New",
            "severity": attack_conf_level,
            "score": attack_conf_score
        }

    # Populate incident hosts/users if incident exists
    if incident:
        hosts = {b.get("computer") for b in grouped_rows if b.get("computer")}
        users = {b.get("user") for b in grouped_rows if b.get("user")}
        incident["hosts"] = sorted(hosts)
        incident["users"] = sorted(users)

    # -------------------------------------------------------------------------
    # 🔴 UPDATED LOGIC: Construct correlation campaigns and details
    # -------------------------------------------------------------------------
    
    # 1. Campaigns
    correlation_campaigns = []
    if not campaigns_df.empty:
        for _, row in campaigns_df.iterrows():
            correlation_campaigns.append({
                "corr_id": row.get("corr_id"),
                "base_image": row.get("base_image"),
                "highest_kill_chain": row.get("highest_kill_chain") or "Execution",
                "max_confidence": int(row.get("max_confidence", 0) or 0),
                "status": row.get("status") or "active",
            })
    
    # 2. Details (using explicitly loaded detail DF sorted by time)
    corr_detail_df = load_correlations_detail(run_id)
    correlations_detail = []
    if not corr_detail_df.empty:
        for _, row in corr_detail_df.iterrows():
            correlations_detail.append({
                "corr_id": row.get("corr_id"),
                "start_time": row.get("start_time"),
                "end_time": row.get("end_time"),
                "base_image": row.get("base_image"),
                "kill_chain_stage": row.get("kill_chain_stage"),
                "event_ids": row.get("event_ids"),
                # Maintaining other useful fields for the UI context usually found in 'correlations'
                "description": row.get("description"),
                "severity": row.get("severity"),
                "confidence": row.get("confidence"),
                "computer": row.get("computer"),
            })

    # Calculate Top 10 Dangerous Bursts using real ranking logic
    # Note: top_dangerous_bursts variable is overwritten below for context to be the baseline rows per user request
    # real_top_dangerous_bursts = rank_dangerous_bursts(burst_aggregates)

    # -------------------------------------------------------------------------
    # 🔴 NEW LOGIC: Calculate events_per_hour
    # -------------------------------------------------------------------------
    # Ensure event_time exists for the logic below if only utc_time exists
    if "event_time" not in df.columns and "utc_time" in df.columns:
        df["event_time"] = df["utc_time"]
    
    events_per_hour = []
    if not df.empty and "event_time" in df.columns:
        df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce", utc=True)
        df = df.dropna(subset=["event_time"])

        df["hour_bucket"] = df["event_time"].dt.floor("H")

        eph = (
            df.groupby("hour_bucket")
            .size()
            .reset_index(name="count")
            .sort_values("hour_bucket")
        )

        events_per_hour = [
            {
                "hour": row["hour_bucket"].strftime("%H:%M"),
                "count": int(row["count"]),
            }
            for _, row in eph.iterrows()
        ]

    context: Dict[str, Any] = {
        # ✅ MANDATORY FIX 2: Force Difference in Summary Tile
        "context_run_marker": run_id[:8],
        "time_range": "all",
        "q": "",
        # FIX: Incident object populated above
        "incident": incident,
        # ✅ FIX 3: ADD DEBUG ID
        # 🔴 CHANGE 3: Use passed run_id
        "analysis_run_id": run_id,
        "debug_event_count": len(df),
        # 🔴 CHANGE 3: Use local total_events variable calculated earlier
        "total_events": total_events,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "detections_count": detections_count,
        "top_events": top_events,
        "interesting": interesting,
        "recent": recent,
        "detections": detections.to_dict(orient="records"),
        "timeline": grouped_rows,
        "normalized_detections": normalized_detections.to_dict(orient="records"),
        # ✅ Context fields required by UI
        "attack_conf_score": attack_conf_score,
        "attack_conf_level": attack_conf_level,
        "attack_conf_cap": attack_conf_cap,
        "attack_conf_basis": attack_conf_basis,
        "highest_kill_chain": highest_kill_chain,
        "is_alertable": is_alertable,
        "confidence_trend": confidence_trend,
        # UI Data Layer Fix: Use safe variable
        "correlations_detail": correlations_detail,  # per-burst rows
        "correlation_campaigns": correlation_campaigns, # Updated with new loop logic
        "correlation_hunts": correlation_hunts,
        "correlation_score": correlation_score,
        "burst_aggregates": burst_aggregates,
        # Renamed variable mapped to existing UI Key
        "baseline_execution_context": baseline_execution_context,
        # NEW: Aggregated Baseline Events for UI
        "top_baseline_events": top_baseline_events,
        "top_dangerous_bursts": baseline_execution_context, # Updated as requested to match baseline_rows
        # ✅ FIX: Add baseline_noise_count to return context
        "baseline_noise_count": baseline_noise_count,
        "kill_chain_summary": kill_chain_summary,
        "mitre_summary": mitre_summary,
        "lolbins_summary": lolbins_summary,
        "events_by_severity": events_by_severity,
        "events_per_hour": events_per_hour,
        "analyst_verdict": analyst_verdict,
        "analyst_action": analyst_action,
        "action_priority": action_priority,
        "action_reason": action_reason,
        "dominant_burst": dominant_burst,
        "evidence_state": evidence_state,
        "highest_kill_chain": highest_kill_chain,
    }

    # FIX: Correct debug keys
    print("[DEBUG] baseline_execution_context len:", len(context.get("baseline_execution_context", [])))
    print("[DEBUG] top_baseline_events len:", len(context.get("top_baseline_events", [])))
    print("[DEBUG] detections len:", len(context.get("detections", [])))
    print("[DEBUG] correlation_campaigns len:", len(context.get("correlation_campaigns", [])))
    print("[DEBUG] detections_df rows:", len(detections_df))
    print("DEBUG unique mitre_id:", detections_df["mitre_id"].unique()[:20])
    print("DEBUG unique mitre_tactic:", detections_df["mitre_tactic"].unique()[:20])
    print("DEBUG distinct mitre pairs:\n", detections_df[["mitre_tactic","mitre_id"]].drop_duplicates().head(20))

    # Requested Debug
    print("[DASHBOARD] baseline_noise_count from context =",
    context.get("baseline_noise_count", "MISSING"),
    "len(baseline_execution_context) =",
    len(context.get("baseline_execution_context", [])) if "baseline_execution_context" in context else "MISSING")
    
    return context

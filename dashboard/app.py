from pathlib import Path
import sqlite3
import subprocess
import sys
import io
import hashlib
import uuid   # ✅ FIX: Needed for unique filenames & run_id
from collections import defaultdict
import datetime
import pandas as pd
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    Response,
    jsonify,
    session,
    get_flashed_messages
)
from werkzeug.utils import secure_filename

# ✅ FIX: Separated imports to prevent runtime import errors
# ❌ REMOVED process_log_upload
# ✅ ADDED ingest_upload, persist_case
from .analysis_engine import (
    run_full_analysis,
    ingest_upload,
    persist_case,
)

from .analysis_cache import (
    get_analysis_snapshot,
    set_analysis_snapshot,
    clear_analysis_snapshot,
)


# 🟡 IMPORTANT ISSUE #6: BASELINE LEAK EXPLANATION
# NOTE: baseline_execution_context is GLOBAL across runs by design.
# It represents long-term host behavior learning, not per-case context.
# Detection logic is run-scoped; baseline is cumulative.

# -------------------------------------------------------------------
# App + paths
# -------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "sysmon.db"
DATA_DIR = BASE_DIR / "data"
TEMPLATES_DIR = BASE_DIR / "dashboard" / "templates"

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
print(">>> LIVE TEMPLATE FOLDER:", app.template_folder)
app.secret_key = "dev-secret-change-later" 

app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

# -------------------------------------------------------------------
# DB init 
# -------------------------------------------------------------------
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

    # ✅ ADD THIS: correlation_campaigns summary table
    # UPDATED to match the Composite Primary Key schema used in analysis_engine.py
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

# -------------------------------------------------------------------
# Helpers: load events / detections 
# -------------------------------------------------------------------
def load_events(run_id=None) -> pd.DataFrame:
    if not DB_PATH.exists() or not run_id:
        return pd.DataFrame()

    conn = get_db_connection()
    query = "SELECT * FROM events WHERE run_id = ? ORDER BY event_time DESC LIMIT 50000"
    
    try:
        df = pd.read_sql_query(query, conn, params=[run_id])
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()

    if df.empty:
        return df

    rename_map = {
        "pid": "process_id",
        "ppid": "parent_process_id",
        "file_path": "target_filename",
        "src_ip": "source_ip",
        "dst_ip": "destination_ip",
    }
    df = df.rename(columns=rename_map)

    if "event_time" in df.columns:
        df["utc_time"] = df["event_time"]

    for col in ["description", "computer", "tags"]:
        if col not in df.columns:
            df[col] = ""

    df["tags"] = df["tags"].fillna("").apply(
        lambda x: [t for t in str(x).split(",") if t]
    )

    return df

def load_detections(run_id=None) -> pd.DataFrame:
    if not DB_PATH.exists() or not run_id:
        return pd.DataFrame()

    conn = get_db_connection()

    try:
        query = "SELECT * FROM detections WHERE run_id = ? ORDER BY event_time DESC LIMIT 10000"
        det = pd.read_sql_query(query, conn, params=[run_id])
    except Exception:
        det = pd.DataFrame()
    finally:
        conn.close()

    if det.empty:
        return det

    expected_cols = [
        "rule_id", "rule_name", "mitre_id", "mitre_tactic",
        "kill_chain_stage", "image", "description", "utc_time",
        "event_id", "severity", "computer", "process_id",
        "parent_process_id", "parent_image", "source_ip",
        "source_port", "destination_ip", "destination_port",
        "target_filename", "confidence_score",
    ]
    
    for col in expected_cols:
        if col not in det.columns:
            det[col] = None

    return det

def load_correlations(run_id=None) -> pd.DataFrame:
    if not DB_PATH.exists() or not run_id:
        return pd.DataFrame()

    conn = get_db_connection()
    try:
        df = pd.read_sql_query("SELECT * FROM correlations WHERE run_id = ?", conn, params=[run_id])
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df

# ✅ FIX #5: Helper now strictly requires run_id
def load_incident_row(incident_id: str, run_id: str) -> dict | None:
    if not DB_PATH.exists() or not run_id:
        return None
    conn = get_db_connection()
    cur = conn.cursor()
    # ✅ FIX: Scoped by run_id
    cur.execute(
        "SELECT incident_id, status, severity, confidence, escalation, analyst, "
        "notes, created_at, updated_at FROM incidents WHERE incident_id = ? AND run_id = ?",
        (incident_id, run_id),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    keys = [
        "incident_id", "status", "severity", "confidence",
        "escalation", "analyst", "notes", "created_at", "updated_at",
    ]
    return dict(zip(keys, row))

def load_behaviors(run_id=None) -> pd.DataFrame:
    if not DB_PATH.exists() or not run_id:
        return pd.DataFrame()

    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            "SELECT * FROM behaviors WHERE run_id = ? ORDER BY event_time DESC",
            conn,
            params=[run_id]
        )
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df

# -------------------------------------------------------------------
# Routes: setup + uploads
# -------------------------------------------------------------------

@app.route("/")
def setup_page():
    if "analysis_run_id" in session:
        old_id = session.pop("analysis_run_id")
        clear_analysis_snapshot(old_id)
        
    _ = get_flashed_messages() 
        
    return render_template("welcome_upload.html")

@app.route("/welcome")
def welcome_page():
    if "analysis_run_id" in session:
        old_id = session.pop("analysis_run_id")
        clear_analysis_snapshot(old_id)
    _ = get_flashed_messages()
    return render_template("welcome_upload.html")

@app.route("/setup", methods=["POST"], endpoint="setup_upload")
def setup_upload():
    xml_file = request.files.get("sysmon_xml")
    rules_file = request.files.get("rules_file")

    if not xml_file or xml_file.filename == "":
        flash("Please upload a Sysmon XML file.")
        return redirect(url_for("welcome_page"))

    upload_id = uuid.uuid4().hex
    run_id = upload_id 

    run_dir = DATA_DIR / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    xml_path = run_dir / "sysmon.xml"
    xml_file.save(str(xml_path))

    rules_dest = None
    if rules_file and rules_file.filename:
        rules_ext = Path(rules_file.filename).suffix.lower()
        if rules_ext not in (".yar", ".yara"):
            flash("Only .yar or .yara files are supported for YARA rules.")
            return redirect(url_for("welcome_page"))
        
        rules_dest = run_dir / f"rules{rules_ext}"
        rules_file.save(str(rules_dest))

    try:
        # 🔥 CORRECT INGESTION PIPELINE
        events_df, detections_df, behaviors_df = ingest_upload(
            xml_path=xml_path,
            rules_path=rules_dest,
        )

        persist_case(events_df, detections_df, behaviors_df)

        run_id = events_df["run_id"].iloc[0]
        session["analysis_run_id"] = run_id

        clear_analysis_snapshot(run_id)

        flash("Files uploaded successfully. Analysis generated.")
        return redirect(url_for("dashboard", run_id=run_id))

    except Exception as e:
        print(f"Error during processing: {e}")
        flash(f"Error processing files: {e}", "error")
        return redirect(url_for("welcome_page"))

# -------------------------------------------------------------------
# Dashboard
# -------------------------------------------------------------------

@app.route("/dashboard/<run_id>")
def dashboard(run_id):
    print("🔥 DASHBOARD USING run_id =", run_id)
    session["analysis_run_id"] = run_id

    # ✅ FIX #3: Dashboard runs analysis AND SAVES SNAPSHOT
    # This guarantees the Source of Truth is created here.
    print("[DASHBOARD] RUNNING FRESH ANALYSIS & SNAPSHOTTING for", run_id)
    context = run_full_analysis(run_id)
    set_analysis_snapshot(run_id, context)
    
    if not context:
        flash("Analysis failed or expired. Please re-upload.", "error")
        return redirect(url_for("welcome_page"))

    context["run_id"] = run_id

    # --- SAFETY BLOCK: Ensure baseline context exists ---
    context.setdefault("baseline_execution_context", [])
    context.setdefault("baseline_noise_count", len(context["baseline_execution_context"]))
    
    # ✅ FIX #1: REMOVED attack_conf_cap and reason from render (Option A)
    return render_template(
        "index.html",
        run_id=run_id,
        severity_counts=context.get("events_by_severity", {}),
        correlation_campaigns=context.get("correlation_campaigns", []),
        correlations_detail=context.get("correlations_detail", []), 
        lolbins_summary=context.get("lolbins_summary", []),
        
        # ✅ FIX: Change filter name to match UI expectation
        time_range=context.get("time_range", "all"),
        
        q=context.get("q", ""),
        attack_conf_score=context.get("attack_conf_score"),
        attack_conf_level=context.get("attack_conf_level"),
        attack_conf_basis=context.get("attack_conf_basis"),
        
        # ✅ FIX: Pass Cap and Alert status
        attack_conf_cap=context.get("attack_conf_cap"),
        is_alertable=context.get("is_alertable", False),
        
        correlation_score=context.get("correlation_score", 0),
        effective_urgency=context.get("effective_urgency"),
        next_expected_stage=context.get("next_expected_stage"),
        missing_evidence=context.get("missing_evidence", []),
        dominant_burst=context.get("dominant_burst"),
        confidence_trend=context.get("confidence_trend", []),
        analyst_verdict=context.get("analyst_verdict"),
        analyst_action=context.get("analyst_action"),
        action_priority=context.get("action_priority"),
        action_reason=context.get("action_reason"),
        response_tasks=context.get("response_tasks", []),
        incident=context.get("incident"),
        source_file_hash=context.get("source_file_hash"), 
        kill_chain_summary=context.get("kill_chain_summary", []),
        kc_severity=context.get("kc_severity", {}),
        evidence_state=context.get("evidence_state", {}),
        correlation_hunts=context.get("correlation_hunts", []),
        highest_kill_chain=context.get("highest_kill_chain"),
        total_events=context.get("total_events", 0),
        high_count=context.get("high_count", 0),
        medium_count=context.get("medium_count", 0),
        low_count=context.get("low_count", 0),
        detections_count=context.get("detections_count", 0),
        events_by_severity=context.get("events_by_severity", {"high": 0, "medium": 0, "low": 0}),
        events_per_hour=context.get("events_per_hour", []),
        top_events=context.get("top_events", []),
        mitre_summary=context.get("mitre_summary", []),
        burst_aggregates=(context.get("burst_aggregates", []) or [])[:10],
        interesting=(context.get("interesting", []) or [])[:30],
        recent=(context.get("recent", []) or [])[:50],
        detections=context.get("detections", []),
        correlations=context.get("correlations", []),
        timeline=context.get("timeline", []), # Kept for safety but UI should use bursts
        baseline_noise_count=context.get("baseline_noise_count", 0),
        baseline_execution_context=context.get("baseline_execution_context", []),
        baseline_stats=context.get("baseline_execution_context", []),
        top_dangerous_bursts=context.get("top_dangerous_bursts", []),
    )

# -------------------------------------------------------------------
# Incident lifecycle actions
# -------------------------------------------------------------------
@app.route("/details")
def details():
    run_id = session.get("analysis_run_id")
    if not run_id:
        return redirect(url_for("welcome_page"))

    # READ ONLY SNAPSHOT. Redirect if missing.
    context = get_analysis_snapshot(run_id)

    if not context:
        flash("Please open dashboard first to initialize analysis.")
        return redirect(url_for("dashboard", run_id=run_id))

    return render_template(
        "details.html",
        # this is the key line
        analysis_run_id=context.get("analysis_run_id", run_id),
        incident=context.get("incident"),
        timeline=context.get("timeline", []),
        detections=context.get("detections", []),
        correlations=context.get("correlations", []),
    )

@app.route("/incident/update", methods=["POST"])
def update_incident():
    run_id = session.get("analysis_run_id")
    incident_id = request.form.get("incident_id")
    
    if not incident_id or not run_id:
        return redirect(url_for("dashboard", run_id=run_id))

    action = request.form.get("action", "save")
    analyst = request.form.get("analyst", "").strip()

    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

    status = None
    escalation = None
    if action == "false_positive":
        status = "Closed - False Positive"
        escalation = "False Positive"
    elif action == "escalate":
        status = "Escalated"
        escalation = "Incident"
    elif action == "close_benign":
        status = "Closed - Benign"
        escalation = "Benign"
    elif action == "save":
        status = request.form.get("status") or None

    try:
        # ✅ FIX #5: Added AND run_id = ? to updates
        if status:
            cur.execute(
                """
                UPDATE incidents
                SET status = ?,
                    escalation = COALESCE(?, escalation),
                    analyst = COALESCE(?, analyst),
                    updated_at = ?
                WHERE incident_id = ? AND run_id = ?
                """,
                (status, escalation, analyst or None, now, incident_id, run_id),
            )
        else:
            cur.execute(
                """
                UPDATE incidents
                SET analyst = COALESCE(?, analyst),
                    updated_at = ?
                WHERE incident_id = ? AND run_id = ?
                """,
                (analyst or None, now, incident_id, run_id),
            )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("dashboard", run_id=run_id))

@app.route("/incident/note", methods=["POST"])
def add_incident_note():
    run_id = session.get("analysis_run_id")
    incident_id = request.form.get("incident_id")
    note = (request.form.get("note") or "").strip()
    
    if not incident_id or not note or not run_id:
        return redirect(url_for("dashboard", run_id=run_id))

    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # ✅ FIX #5: Scoped select
        cur.execute(
            "SELECT notes FROM incidents WHERE incident_id = ? AND run_id = ?",
            (incident_id, run_id),
        )
        row = cur.fetchone()
        existing = row['notes'] if row and row['notes'] else "" 
        new_block = f"[{now}] {note}"
        combined = (existing + "\n" + new_block).strip() if existing else new_block
        
        # ✅ FIX #5: Scoped update
        cur.execute(
            """
            UPDATE incidents
            SET notes = ?, updated_at = ?
            WHERE incident_id = ? AND run_id = ?
            """,
            (combined, now, incident_id, run_id),
        )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("dashboard", run_id=run_id))

# -------------------------------------------------------------------
# Process detail view
# -------------------------------------------------------------------
@app.route("/process/<path:image>")
def process_view(image):
    # ✅ FIX #4: DO NOT use secure_filename here.
    # It destroys paths like "C:\Windows\System32\svchost.exe" -> "Windows_System32_svchost.exe"
    # which causes the DB lookup to fail. We just strip whitespace.
    image = image.strip()
    
    if not image:
        return "Missing image parameter", 400

    run_id = session.get("analysis_run_id")
    df = load_events(run_id)
    
    if df.empty:
        proc_df = df.iloc[0:0]
        parent_summary = []
        child_summary = []
        total = 0
    else:
        proc_df = df[df["image"] == image]
        total = len(proc_df)

        if "parent_image" in proc_df.columns:
            parent_summary_df = (
                proc_df.groupby("parent_image")
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
            )
            parent_summary = parent_summary_df.to_dict(orient="records")
        else:
            parent_summary = []

        if "image" in df.columns:
            child_df = (
                df[df["parent_image"] == image]
                if "parent_image" in df.columns
                else df.iloc[0:0]
            )
            if not child_df.empty:
                child_summary_df = (
                    child_df.groupby("image")
                    .size()
                    .reset_index(name="count")
                    .sort_values("count", ascending=False)
                )
                child_summary = child_summary_df.to_dict(orient="records")
            else:
                child_summary = []
        else:
            child_summary = []

    return render_template(
        "process.html",
        image=image,
        events=proc_df.to_dict(orient="records"),
        total=total,
        parent_summary=parent_summary,
        child_summary=child_summary,
    )

# -------------------------------------------------------------------
# Burst View Route
# -------------------------------------------------------------------
@app.route("/burst/")
@app.route("/burst")
def burst_missing_redirect():
    run_id = session.get("analysis_run_id")
    if run_id:
        return redirect(url_for('dashboard', run_id=run_id))
    return redirect(url_for('welcome_page'))

@app.route("/burst/<burst_id>")
def burst_view(burst_id):
    run_id = session.get("analysis_run_id")
    if not run_id:
        return redirect(url_for("welcome_page"))

    # ✅ FIX #3: READ SNAPSHOT ONLY
    context = get_analysis_snapshot(run_id)
    
    if not context or "burst_aggregates" not in context:
        flash("Burst data not found. Please refresh the Dashboard.")
        return redirect(url_for("dashboard", run_id=run_id))

    all_bursts = (
        context.get("burst_aggregates", []) +
        context.get("top_dangerous_bursts", []) +
        context.get("timeline", [])
    )

    burst = next(
        (b for b in all_bursts if str(b.get("burst_id")) == str(burst_id)),
        None
    )

    if not burst:
        return f"Burst not found: {burst_id}", 404

    image = burst.get("image")
    start = burst.get("start_time")
    end = burst.get("end_time")

    if not image or not start or not end:
        return f"Invalid burst metadata for ID: {burst_id}", 500

    if not DB_PATH.exists():
        flash("Please upload Sysmon and detection files first.")
        return redirect(url_for("setup_page"))

    conn = get_db_connection()
    cur = conn.cursor()

    # 1. Pull events for this burst
    cur.execute(
        """
        SELECT
            event_time, event_id, image, parent_image, command_line, user,
            pid, ppid, src_ip, dst_ip, dst_port, file_path, computer
        FROM events
        WHERE image = ?
            AND event_time >= ?
            AND event_time <= ?
            AND run_id = ?
        ORDER BY event_time
        """,
        (image, start, end, run_id),
    )
    rows = cur.fetchall()

    events = []
    for e in rows:
        events.append({
            "event_time": e["event_time"],
            "event_id": e["event_id"],
            "parent_image": e["parent_image"],
            "command_line": e["command_line"],
            "file_path": e["file_path"],
            "dst_ip": e["dst_ip"],
            "dst_port": e["dst_port"],
            "src_ip": e["src_ip"],
            "user": e["user"],
            "image": e["image"]
        })

    # 2. Find child processes
    cur.execute(
        """
        SELECT DISTINCT image
        FROM events
        WHERE parent_image = ?
            AND event_time >= ?
            AND event_time <= ?
            AND run_id = ?
        """,
        (image, start, end, run_id),
    )
    child_rows = cur.fetchall()
    child_images = sorted([r[0] for r in child_rows if r[0]])
    conn.close()

    # 3. Calculate Risk Score
    risk_score = 0
    critical_ids = {'1', '8', '9', '12', '13', '14', '19', '25'} 
    medium_ids = {'3', '11', '17', '18', '22'}

    unique_ids = {str(e.get('event_id')) for e in events}

    if unique_ids & critical_ids:
        risk_score += 60
    if unique_ids & medium_ids:
        risk_score += 20

    if len(events) > 50:
        risk_score += 15
    elif len(events) > 10:
        risk_score += 5

    has_external_net = False
    for e in events:
        d_ip = e.get('dst_ip')
        if d_ip and not (d_ip.startswith('10.') or d_ip.startswith('192.168.') or d_ip.startswith('127.') or d_ip.startswith('172.16.')):
                has_external_net = True
                break
    if has_external_net:
        risk_score += 10

    risk_score = min(risk_score, 100)

    # 4. Construct Metadata
    parent_images = sorted(
        {e["parent_image"] for e in events if e.get("parent_image")}
    )
    processes_in_burst = sorted(
        {e.get("image") for e in events if e.get("image")}
    )
    
    # ✅ FIX: Explicitly add event_ids for use in templates/analysis
    event_ids = [e.get("event_id") for e in events if e.get("event_id") is not None]

    burst_meta = {
        "burst_id": burst_id,
        "image": image,
        "start_time": start,
        "end_time": end,
        "event_count": len(events),
        "risk_score": risk_score,
        "event_ids": event_ids  # ✅ Added for completeness
    }

    process_summary = {
        "parents": parent_images,
        "children": child_images,
        "processes": processes_in_burst,
    }

    return render_template(
        "burst.html",
        burst=burst_meta,
        process_summary=process_summary,
        events=events,
    )

# -------------------------------------------------------------------
# CSV exports
# -------------------------------------------------------------------
@app.route("/api/events.csv")
def export_events_csv():
    run_id = session.get("analysis_run_id")
    df = load_events(run_id)
    if df.empty:
        return "No events available", 404

    out = io.StringIO()
    df_out = df.copy()
    df_out["tags"] = df_out["tags"].apply(
        lambda lst: ",".join(lst) if isinstance(lst, list) else lst
    )
    df_out.to_csv(out, index=False)
    out.seek(0)

    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )

@app.route("/api/detections.csv")
def export_detections_csv():
    run_id = session.get("analysis_run_id")
    det = load_detections(run_id)
    if det.empty:
        return "No detections available", 404

    out = io.StringIO()
    det.to_csv(out, index=False)
    out.seek(0)

    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=detections.csv"},
    )

@app.route("/raw-events")
def raw_events():
    if not DB_PATH.exists():
        flash("Please upload Sysmon and detection files first.")
        return redirect(url_for("setup_page"))

    run_id = session.get("analysis_run_id")
    if not run_id:
        return redirect(url_for("welcome_page"))

    page = int(request.args.get("page", 1))
    page_size = 50
    offset = (page - 1) * page_size

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT event_time, event_id, image, user, src_ip, dst_ip, command_line "
        "FROM events WHERE run_id = ? ORDER BY event_time DESC LIMIT ? OFFSET ?",
        (run_id, page_size, offset),
    )
    rows = cur.fetchall()
    conn.close()

    events = [
        {
            "event_time": r["event_time"],
            "event_id": r["event_id"],
            "image": r["image"],
            "user": r["user"],
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "command_line": r["command_line"],
        }
        for r in rows
    ]
    has_next = len(events) == page_size

    return render_template(
        "raw_events.html",
        analysis_run_id=run_id,   # <- needed for Back to Summary
        events=events,
        page=page,
        has_next=has_next,
    )

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
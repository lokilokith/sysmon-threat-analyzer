import argparse
import sys
import json
import logging
import datetime
import webbrowser
from pathlib import Path

# Fix import paths to allow running from root
sys.path.append(str(Path(__file__).resolve().parent))

# Import Engine Logic (Without refactoring internal engine structure yet)
try:
    from dashboard.db import init_db
    from dashboard.analysis_engine import ingest_upload, persist_case, run_full_analysis
except ImportError:
    # Fallback if run from different context
    sys.exit("Error: Could not import engine. Run from root directory.")

import os
import contextlib
import warnings

# --- CONFIGURATION ---
TOOL_NAME = "Sysmon Threat Analyzer"

# Configure Logging (Quiet by default as per request for clean output, but errors to stderr)
logging.basicConfig(level=logging.ERROR, format="%(message)s")

class QuietExecution:
    """Context manager to suppress stdout and stderr."""
    def __enter__(self):
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        sys.stdout = open(os.devnull, 'w', encoding='utf-8')
        sys.stderr = open(os.devnull, 'w', encoding='utf-8')
        # Also suppress warnings
        warnings.simplefilter("ignore")

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout.close()
        sys.stderr.close()
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr
        warnings.resetwarnings()

def get_timestamp_str():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")

def cmd_analyze(args):
    input_file = args.input_file
    output_dir = args.out
    rules_path = args.rules

    if not input_file.exists():
        sys.exit(f"Error: Input file not found: {input_file}")

    # 1. Init DB -- SILENT
    with QuietExecution():
        init_db()

    # 2. Ingest -- SILENT
    try:
        with QuietExecution():
            events_df, detections_df, behaviors_df = ingest_upload(
                xml_path=input_file,
                rules_path=rules_path
            )
        if events_df.empty:
            sys.exit("Error: No events found in XML.")
        
        run_id = events_df["run_id"].iloc[0]
        with QuietExecution():
            persist_case(events_df, detections_df, behaviors_df)
    except Exception as e:
        logging.exception("Ingestion failed")
        sys.exit("Error during ingestion. See logs.")

    # 3. Analyze -- SILENT
    try:
        with QuietExecution():
            context = run_full_analysis(run_id)
        if not context:
            sys.exit("Error: Analysis failed.")
    except Exception as e:
        logging.exception("Analysis failed")
        sys.exit("Error during analysis. See logs.")

    # 4. Generate Artifacts
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a specific run directory to keep things organized
    run_dir = output_dir / f"run_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    def write_json(path: Path, data):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    # ① summary.json
    summary = {
        "run_id": run_id,
        "total_events": context.get("total_events", 0),
        "detections_count": context.get("detections_count", 0),
        "attack_confidence": {
            "score": context.get("attack_conf_score", 0),
            "level": context.get("attack_conf_level", "Unknown"),
            "highest_kill_chain": context.get("highest_kill_chain", "None")
        },
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z"
    }
    write_json(run_dir / "summary.json", summary)

    # ② detections.json
    dets = context.get("detections", [])
    formatted_dets = []
    # Handle if detections is DataFrame (convert to list of dicts)
    if hasattr(dets, "to_dict"):
        dets = dets.to_dict(orient="records")
        
    for d in dets:
        formatted_dets.append({
            "rule_name": d.get("rule_name"),
            "mitre_id": d.get("mitre_id"),
            "severity": d.get("severity"),
            "confidence_score": d.get("confidence_score"),
            "image": d.get("image"),
            "computer": d.get("computer"),
            "time": d.get("utc_time")
        })
    write_json(run_dir / "detections.json", formatted_dets)

    # ③ campaigns.json
    campaigns = []
    for c in context.get("correlation_campaigns", []):
        campaigns.append({
            "campaign_id": c.get("corr_id"),
            "base_image": c.get("base_image"),
            "status": c.get("status"),
            "max_confidence": c.get("max_confidence"),
            "highest_kill_chain": c.get("highest_kill_chain")
        })
    write_json(run_dir / "campaigns.json", campaigns)

    # ④ bursts.json
    bursts = []
    # Use burst_aggregates for high-level grouped anomalies
    for b in context.get("burst_aggregates", []):
         bursts.append({
             "burst_id": b.get("burst_id"),
             "image": b.get("image"),
             "kill_chain_stage": b.get("kill_chain_stage"),
             "risk_score": b.get("peak_score"), 
             "classification": (
                 "attack_candidate" if int(b.get("peak_score", 0)) >= 40 else "background_activity"
             ),
             "event_ids": b.get("event_ids", []),
             "confidence_reasons": b.get("confidence_reasons", [])
         })
    write_json(run_dir / "bursts.json", bursts)

    # ⑤ mitre.json
    mitre = []
    for m in context.get("mitre_summary", []):
        mitre.append({
            "tactic": m.get("mitre_tactic"),
            "technique": m.get("mitre_id"),
            "count": m.get("count")
        })
    write_json(run_dir / "mitre.json", mitre)

    # ⑥ metadata.json
    metadata = {
        "tool": TOOL_NAME,
        "analysis_mode": "batch",
        "input_file": str(input_file.name),
        "command": "analyze",
        "analyzed_at": datetime.datetime.utcnow().isoformat() + "Z"
    }
    write_json(run_dir / "metadata.json", metadata)

    # 5. Console Output (Strict Format)
    _print_summary(context, run_id)
    print(f"Results saved to : {run_dir.resolve()}")

    # 6. Dashboard Link (Variable needed for --open)
    dashboard_url = f"http://127.0.0.1:5000/dashboard/{run_id}"

    if args.open:
        print(f"🚀 Launching browser...")
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            print(f"Could not open browser automatically.")

    # 7. Optional: Serve Dashboard (Blocking)
    if args.serve:
        print("-" * 36)
        print("🟢 Starting Local Dashboard Server...")
        print("Press CTRL+C to stop.")
        print("-" * 36)
        try:
            from dashboard.app import app
            # Run without debug to avoid reloader issues in CLI wrapper
            app.run(host="127.0.0.1", port=5000, debug=False)
        except ImportError:
            print("Error: Could not import dashboard app.")
        except Exception as e:
            print(f"Server error: {e}")

def _get_verdict_text(context):
    # Use the engine's alertable flag if available, otherwise strict fallback
    if context.get("is_alertable") or context.get("attack_conf_score", 0) >= 40:
        return "Attack patterns detected. Analyst review required."
    else:
        return "No confirmed attack patterns detected."

def _print_summary(context, run_id):
    total = context.get("total_events", 0)
    dets = context.get("detections_count", 0)
    score = context.get("attack_conf_score", 0)
    level = context.get("attack_conf_level", "Unknown")
    killchain = context.get("highest_kill_chain") or "None"
    campaigns = len(context.get("correlation_campaigns", []))
    
    verdict = _get_verdict_text(context)

    print("=" * 36)
    print("Sysmon Threat Analyzer")
    print("=" * 36)
    print(f"Run ID           : {run_id}")
    print(f"Total Events     : {total}")
    print(f"Detections       : {dets}")
    print(f"Attack Confidence: {level.upper()} ({score})")
    print(f"Highest Killchain: {killchain}")
    print(f"Campaigns        : {campaigns}")
    print("")
    print(f"Verdict: {verdict}")
    print("=" * 36)

def interactive_menu():
    while True:
        print("\n" + "="*40)
        print("   SYSMON THREAT ANALYZER - MENU")
        print("="*40)
        print("1. CLI Analysis Mode (Strict Report)")
        print("2. Dashboard Mode (Interactive UI)")
        print("3. Exit")
        print("-" * 40)
        
        choice = input("Select an option [1-3]: ").strip()
        
        if choice == "1":
            # CLI Mode
            # Strip quotes in case user pastes path as "C:\path\..."
            xml_in = input("Enter path to Sysmon XML file: ").strip().strip('"').strip("'")
            out_dir = input("Enter output directory (default: reports/): ").strip().strip('"').strip("'") or "reports/"
            
            if not xml_in:
                print("Error: Input file must be provided.")
                continue

            # Mock arguments object
            class Args:
                input_file = Path(xml_in)
                out = Path(out_dir)
                rules = None
                open = False
                serve = False
            
            print(f"\n[INFO] Starting analysis on {xml_in}...")
            print("(Please wait, processing events...)")
            cmd_analyze(Args())
            
            # Post-Analysis Menu
            while True:
                print("\n[NEXT STEPS]")
                print("1. Analyze another file")
                print("2. Switch to Dashboard Mode")
                print("3. Return to Main Menu")
                print("4. Exit")
                sub_choice = input("Select [1-4]: ").strip()
                
                if sub_choice == "1":
                    break # Break inner loop, returns to main loop prompt? No, main loop prompts menu.
                          # User wants "Analyze another file" -> easiest is just break to main menu or recursive?
                          # Let's break to main menu where they can select 1 again. 
                          # Actually, forcing them to main menu is fine.
                    break
                elif sub_choice == "2":
                    # Directly jump to dashboard mode logic? Or break to main menu and tell them to pick 2?
                    # Let's run dashboard logic here for convenience.
                    print("\n[INFO] Starting Dashboard Server...")
                    print("Please open your browser to: http://127.0.0.1:5000")
                    print("Press CTRL+C to stop.")
                    try:
                        from dashboard.app import app
                        app.run(host="127.0.0.1", port=5000, debug=False)
                    except ImportError:
                        print("Error: Could not import dashboard app.")
                    except KeyboardInterrupt:
                        print("\nServer stopped.")
                        break # Go back to main menu
                elif sub_choice == "3":
                    break # Back to main menu
                elif sub_choice == "4":
                    sys.exit(0)
                else:
                    print("Invalid choice.")

        elif choice == "2":
            # Dashboard Mode
            print("\n[INFO] Starting Dashboard Server...")
            print("Please open your browser to: http://127.0.0.1:5000")
            print("Press CTRL+C to stop.")
            try:
                from dashboard.app import app
                app.run(host="127.0.0.1", port=5000, debug=False)
            except ImportError:
                print("Error: Could not import dashboard app.")
            except Exception as e:
                print(f"Server error: {e}")
            except KeyboardInterrupt:
                print("\nServer stopped.")
                # Loop continues to main menu
                
        elif choice == "3":
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(description="Sysmon Threat Analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze command
    parser_analyze = subparsers.add_parser("analyze")
    parser_analyze.add_argument("input_file", type=Path, help="Path to Sysmon XML file")
    parser_analyze.add_argument("--rules", type=Path, help="Path to YARA rules directory/file")
    parser_analyze.add_argument("--out", type=Path, required=True, help="Output directory")
    parser_analyze.add_argument("--open", action="store_true", help="Open the dashboard after analysis")
    parser_analyze.add_argument("--serve", action="store_true", help="Start the dashboard server after analysis")
    parser_analyze.set_defaults(func=cmd_analyze)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

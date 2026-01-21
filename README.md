# Sysmon Threat Analyzer

**A professional SOC tool for offline detection of advanced threats in Sysmon XML logs.**

## 🎯 What Problem It Solves
SOC teams often face "alert fatigue" when dealing with massive log files. This tool helps analysts **triage large Sysmon XML logs** and **identify suspicious behavior patterns** (like bursts of activity) without relying solely on static signatures.

It is designed to confirm: *"Is this machine compromised?"*

## 🚀 Key Features
*   **Behavioral Analysis**: Detects attack bursts (Process, Network, File) rather than just single events.
*   **Correlation Engine**: Groups disparate events into cohesive "Campaigns".
*   **MITRE ATT&CK Mapping**: Automatically maps activity to kill-chain stages (e.g., T1059 Command and Scripting Interpreter).
*   **Audit-Ready**: Generates structured JSON reports for SIEM integration.

## 📦 How to Run

The tool is accessed via the `cli.py` wrapper.

### Analyze a File
Process a raw Sysmon XML log and generate a professional report.

```powershell
python cli.py analyze data/sample_sysmon.xml --out reports/
```

## 📊 Understanding the Output

### Console Summary
*   **Run ID**: Unique identifier for the analysis session.
*   **Verdict**: The tool's final assessment (e.g., "Attack patterns detected").
*   **Attack Confidence**:
    *   **Low**: Likely background noise.
    *   **Medium/High**: Strong indicators of compromise.
*   **Highest Killchain**: The most advanced stage of the attack observed (e.g., "Actions on Objectives").

### JSON Report (`reports/run_<id>.json`)
A machine-readable file containing:
*   `detections_count`: Total number of rule hits.
*   `attack_confidence`: Object containing score and level.
*   `verdict`: The final logic-driven conclusion.

## ⚠️ Limitations
*   **Batch Analysis Only**: This is an offline forensic tool, not a real-time EDR agent.
*   **No Live Response**: It analyzes logs but does not block processes or isolate hosts.
*   **Lab-Trained Baselines**: Anomaly detection logic is tuned on lab data; production environments may require whitelist tuning.
*   **Not an EDR**: It complements EDRs by providing detailed post-incident analysis.

## 🛠️ Architecture
*   **Ingestion**: Streaming XML parser (efficient for large files).
*   **Engine**: Hybrid logic (Behavioral + YARA).
*   **Persistence**: SQLite-backed state management.
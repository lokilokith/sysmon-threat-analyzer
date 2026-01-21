from __future__ import annotations

from pathlib import Path
import hashlib
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

import pandas as pd


# -------------------------------------------------------------------
# XML parsing helpers
# -------------------------------------------------------------------

def _get_text(elem: Optional[ET.Element]) -> Optional[str]:
    """Safe text extraction from XML nodes."""
    if elem is None:
        return None
    text = elem.text
    return text.strip() if text is not None else None


def _compute_event_uid(
    computer: Optional[str],
    time_created: Optional[str],
    event_id: Optional[str],
    image: Optional[str],
    pid: Optional[str],
    ppid: Optional[str],
    command_line: Optional[str],
) -> str:
    """
    Deterministic unique ID for a Sysmon event.
    This must be stable across parser/ingestion so dedup works.
    """
    parts = [
        computer or "",
        time_created or "",
        event_id or "",
        image or "",
        pid or "",
        ppid or "",
        command_line or "",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def parse_event(ev: ET.Element) -> Dict[str, Any]:
    """
    Parse a single <Event> element into a flat dict.
    NO DB writes, NO run_id here.
    """
    system = ev.find("./System")
    if system is None:
        system = ev.find(
            "./{http://schemas.microsoft.com/win/2004/08/events/event}System"
        )

    event_id = None
    time_created = None
    computer = None

    if system is not None:
        eid_elem = system.find("EventID") or system.find(
            "{http://schemas.microsoft.com/win/2004/08/events/event}EventID"
        )
        event_id = _get_text(eid_elem)

        tc_elem = system.find("TimeCreated") or system.find(
            "{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated"
        )
        if tc_elem is not None:
            time_created = tc_elem.attrib.get(
                "SystemTime"
            ) or tc_elem.attrib.get("systemTime")

        comp_elem = system.find("Computer") or system.find(
            "{http://schemas.microsoft.com/win/2004/08/events/event}Computer"
        )
        computer = _get_text(comp_elem)

    event_data = ev.find("./EventData") or ev.find(
        "./{http://schemas.microsoft.com/win/2004/08/events/event}EventData"
    )

    data_map: Dict[str, Optional[str]] = {}
    if event_data is not None:
        for d in event_data.findall("Data"):
            name = d.attrib.get("Name")
            if not name:
                continue
            data_map[name.lower()] = _get_text(d)

        for d in event_data.findall(
            "{http://schemas.microsoft.com/win/2004/08/events/event}Data"
        ):
            name = d.attrib.get("Name")
            if not name:
                continue
            key = name.lower()
            if key not in data_map:
                data_map[key] = _get_text(d)

    image = data_map.get("image") or data_map.get("processimage") or data_map.get(
        "path"
    )
    parent_image = data_map.get("parentimage")
    command_line = data_map.get("commandline") or data_map.get("cmdline")
    user = data_map.get("user") or data_map.get("username")
    pid = data_map.get("processid") or data_map.get("pid")
    ppid = data_map.get("parentprocessid") or data_map.get("ppid")
    src_ip = data_map.get("sourceip") or data_map.get("src_ip")
    dst_ip = data_map.get("destinationip") or data_map.get("dst_ip")
    dst_port = data_map.get("destinationport") or data_map.get("dst_port")
    file_path = (
        data_map.get("targetfilename")
        or data_map.get("filepath")
        or data_map.get("path")
    )

    # Normalize event_id as simple string; ingestion will enforce stricter type
    eid_norm = (event_id or "").strip() or None

    event_uid = _compute_event_uid(
        computer=computer,
        time_created=time_created,
        event_id=eid_norm,
        image=image,
        pid=pid,
        ppid=ppid,
        command_line=command_line,
    )

    return {
        "event_uid": event_uid,
        "utc_time": time_created,
        "event_id": eid_norm,
        "image": image,
        "parent_image": parent_image,
        "command_line": command_line,
        "user": user,
        "pid": pid,
        "ppid": ppid,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "file_path": file_path,
        "severity": None,
        "computer": computer,
        "description": None,
        "tags": None,
        # compatible extra columns used by analysis_engine
        "destination_ip": dst_ip,
        "source_port": None,
        "target_filename": file_path,
        "process_id": pid,
        "parent_process_id": ppid,
    }


def load_all_sources_from_xml(xml_path: str | Path) -> List[Dict[str, Any]]:
    """
    Parse a Sysmon XML file into a list of event dicts.

    This uses robust OR logic to handle both namespaced and non-namespaced
    <Event> elements, and raises if no events are found.
    """
    xml_path = Path(xml_path)
    if not xml_path.exists():
        raise FileNotFoundError(f"Sysmon XML not found: {xml_path}")

    tree = ET.parse(xml_path)
    root = tree.getroot()

    events: List[ET.Element] = []
    events.extend(
        root.findall(
            ".//{http://schemas.microsoft.com/win/2004/08/events/event}Event"
        )
    )
    events.extend(root.findall(".//Event"))

    # De-duplicate by object id
    events = list({id(e): e for e in events}.values())

    if not events:
        raise RuntimeError(
            "XML parsed successfully but NO <Event> elements were found. "
            "Check namespace format."
        )

    print(f"DEBUG: Found {len(events)} raw XML events. Parsing now...")
    rows = [parse_event(ev) for ev in events]
    return rows


# Optional helper to get a DataFrame directly
def parse_xml_to_dataframe(xml_path: str | Path) -> pd.DataFrame:
    rows = load_all_sources_from_xml(xml_path)
    return pd.DataFrame(rows)


# -------------------------------------------------------------------
# Detection rules
# -------------------------------------------------------------------

def find_detections(df: pd.DataFrame) -> pd.DataFrame:
    """
    Minimal heuristic detection:
    treat some event_ids as mapped to MITRE so UI has data.
    """
    cols = [
        "rule_id", "rule_name", "mitre_id", "mitre_tactic",
        "kill_chain_stage", "utc_time", "image", "event_id",
        "description", "severity", "computer", "process_id",
        "parent_process_id", "parent_image", "source_ip",
        "source_port", "destination_ip", "destination_port",
        "target_filename", "confidence_score",
    ]
    if df.empty:
        return pd.DataFrame(columns=cols)

    hits: List[Dict[str, Any]] = []

    mitre_map = {
        "1": ("T1059", "Execution"),
        "3": ("T1071", "Command and Control"),
        "11": ("T1105", "Persistence"),
        "22": ("T1071", "Command and Control"),
    }

    for _, row in df.iterrows():
        eid = str(row.get("event_id") or "")
        if eid not in mitre_map:
            continue

        mitre_id, tactic = mitre_map[eid]
        kill_stage = tactic or "Execution"

        hits.append({
            "rule_id": f"heur-{eid}",
            "rule_name": f"Heuristic {eid}",
            "mitre_id": mitre_id,
            "mitre_tactic": tactic,
            "kill_chain_stage": kill_stage,
            "utc_time": row.get("utc_time"),
            "image": row.get("image"),
            "event_id": row.get("event_id"),
            "description": row.get("description"),
            "severity": row.get("severity"),
            "computer": row.get("computer"),
            "process_id": row.get("process_id") or row.get("pid"),
            "parent_process_id": row.get("parent_process_id") or row.get("ppid"),
            "parent_image": row.get("parent_image"),
            "source_ip": row.get("source_ip"),
            "source_port": row.get("source_port"),
            "destination_ip": row.get("destination_ip"),
            "destination_port": row.get("destination_port"),
            "target_filename": row.get("target_filename"),
            "confidence_score": 40,
        })

    return pd.DataFrame(hits, columns=cols)
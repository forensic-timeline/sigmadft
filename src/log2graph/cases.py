# src/log2graph/cases.py

"""Case metadata stored in the :Case node of each sigmadft-* database.

A case goes through three stages, each one needing the previous:
    imported      -> log2graph wrote the events and entities
    detected      -> SigmaDFT anomaly detection annotated the events (:Detected)
    reconstructed -> high-level events (HLE) were built from the detections

The node is written by the log2graph CLI and by the web app, so both kinds
of case can be analysed and exported from the web.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

STAGES = ("imported", "detected", "reconstructed")

# Properties of the later stages, cleared when an earlier stage is run again
DETECTION_KEYS = ("rule_source", "detected_at", "detected_events", "detection_output")
RECONSTRUCTION_KEYS = ("reconstructed_at", "hle_count", "grouped_output")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def import_props(database: str, csv_path: str, rows: int, decode: bool) -> Dict[str, Any]:
    props = {"name": database, "source_csv": str(Path(csv_path).resolve()), "rows": rows,
             "decode": decode, "imported_at": now(), "stage": "imported"}
    props.update({k: None for k in DETECTION_KEYS + RECONSTRUCTION_KEYS})
    return props


def detection_props(rule_source: Optional[str], events: int, output_json: Optional[str]) -> Dict[str, Any]:
    props = {"stage": "detected", "rule_source": rule_source, "detected_at": now(),
             "detected_events": events,
             "detection_output": str(Path(output_json).resolve()) if output_json else None}
    props.update({k: None for k in RECONSTRUCTION_KEYS})
    return props


def reconstruction_props(hle_count: int, grouped_json: Optional[str]) -> Dict[str, Any]:
    return {"stage": "reconstructed", "reconstructed_at": now(), "hle_count": hle_count,
            "grouped_output": str(Path(grouped_json).resolve()) if grouped_json else None}


def rule_source_from_name(path: str) -> Optional[str]:
    """'all_decoded_sample.json' -> 'all' (naming rule of the results folder)."""
    prefix = Path(path).name.split("_", 1)[0]
    return prefix if prefix in ("atlas", "sigma", "all") else None

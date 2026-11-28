# src/sigmadft/pipeline.py

"""SigmaDFT analysis steps as library functions.

Used by the CLI (sigmadft/main.py) and by the web app (graph2web), so both
produce the same results:

    low = build_low_timeline(csv_path, decode)
    rules = load_rules(rule_source)
    merged = detect(low, rules)            # one event per matching log line
    grouped = reconstruct(merged)          # adjacent events with the same type
    write_timeline(merged, "x.json")       # or .csv; grouped=True for grouped

timeline_rows() gives the same records as the JSON output, and
undetected_rows() gives every log line in that format with "-" in the
analysis fields (used before any analysis was run).
"""

import csv
import json
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

import sigmadft.analyzers.ReadFromYamlAnalyzer as ReadFromYamlAnalyzer
from sigmadft.adapters import ADAPTERS, get_adapter
from sigmadft.events.HighLevelEvent import HighLevelEvent
from sigmadft.reader.CSVReader import CSVReader
from sigmadft.rules.Rule import Rule
from sigmadft.timelines.HighLevelTimeline import HighLevelTimeline, MergeHighLevelTimeline
from sigmadft.timelines.LowLevelTimeline import LowLevelTimeline

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
RULE_SOURCES = list(ADAPTERS) + ["all"]

# Output fields, in the order of the JSON / CSV output
FIELDS = ["id", "date_time_min", "date_time_max", "evidence_message", "type_candidate",
          "type", "description", "category", "plugin", "files", "keys"]
GROUPED_FIELDS = FIELDS + ["count", "ids"]
# Fields filled by the analysis; "-" before any analysis was run
ANALYSIS_FIELDS = ["type_candidate", "type", "description", "category", "keys"]
NOT_ANALYZED = "-"

Log = Callable[[str], None]
Progress = Callable[[int, int, str], None]


def _quiet(_message: str) -> None:
    pass


def output_stem(input_path: str, rule_source: str, decode: bool) -> str:
    """Output file name without extension, e.g. all_decoded_sample."""
    return f"{rule_source}_{'decoded_' if decode else ''}{Path(input_path).stem}"


def grouped_path(path: str) -> str:
    p = Path(path)
    return str(p.with_name(f"{p.stem}_grouped{p.suffix}"))


# ----------------------------------------------------------------------
# Steps
# ----------------------------------------------------------------------

def build_low_timeline(input_path: str, decode: bool = False) -> LowLevelTimeline:
    low_timeline = LowLevelTimeline()
    low_timeline.create_timeline(CSVReader(input_path), decode=decode)
    return low_timeline


def load_rules(rule_source: str, log: Log = _quiet) -> List[Rule]:
    """Every rule of the source ('atlas', 'sigma' or 'all'), loaded by its adapter."""
    if rule_source not in RULE_SOURCES:
        raise ValueError(f"Unknown rule source '{rule_source}' (use {', '.join(RULE_SOURCES)}).")
    sources = list(ADAPTERS) if rule_source == "all" else [rule_source]
    files = []
    for source in sources:
        adapter = get_adapter(source)
        files.extend((adapter, path) for path in adapter.discover())
    log(f"Running analysis with rule source '{rule_source}' ({len(files)} rules)")
    log("Loading YAML rules ...")

    rules: List[Rule] = []
    for adapter, path in files:
        display_path = os.path.relpath(path, RULES_DIR)
        if not os.path.exists(path):
            log(f"Warning: Rule file not found: {path}")
            continue
        try:
            rule = adapter.load(path)
            rule.rule_file = display_path.replace(os.sep, "/")
            rules.append(rule)
            log(f"  ✓ Loaded rule [{adapter.name}]: {display_path}")
        except Exception as e:
            log(f"  ✗ Error loading rule [{adapter.name}] {display_path}: {str(e)}")
    return rules


def detect(low_timeline: LowLevelTimeline, rules: List[Rule], log: Log = _quiet,
           progress: Optional[Progress] = None) -> Optional[HighLevelTimeline]:
    """Run every rule; returns the merged timeline (one event per log line),
    or None when no rule matched (the CLI then writes no output file)."""
    high_timelines = []
    total = 0
    for i, rule in enumerate(rules, 1):
        if progress:
            progress(i, len(rules), rule.title)
        log(f"[{i}/{len(rules)}] Processing rule: {rule.title} ...")
        start = datetime.now()
        try:
            high_timeline = ReadFromYamlAnalyzer.Run(low_timeline, rule)
            took = _duration((datetime.now() - start).total_seconds())
            if high_timeline and high_timeline.events:
                high_timelines.append(high_timeline)
                total += len(high_timeline.events)
                log(f"  ✓ Found {len(high_timeline.events)} events in {took}")
            else:
                log(f"  ○ No events found in {took}")
        except Exception as e:
            took = _duration((datetime.now() - start).total_seconds())
            log(f"  ✗ Error processing rule in {took}: {str(e)}")
    log(f"  ✓ Total events found: {total}")
    if not high_timelines:
        return None
    return MergeHighLevelTimeline(high_timelines).merge()


def reconstruct(merged: HighLevelTimeline) -> HighLevelTimeline:
    """High-level events: adjacent events with the same type become one."""
    return MergeHighLevelTimeline.group_consecutive_by_type(merged)


# ----------------------------------------------------------------------
# Output records and files
# ----------------------------------------------------------------------

def timeline_rows(timeline: HighLevelTimeline, grouped: bool = False) -> Dict[str, Dict]:
    """Records of the JSON output: {"0": {...}, "1": {...}}."""
    rows = {}
    for index, event in enumerate(timeline.events):
        row = {
            "id": event.id,
            "date_time_min": event.date_time_min,
            "date_time_max": event.date_time_max,
            "evidence_message": event.evidence_message,
            "type_candidate": event.type_candidate,
            "type": event.type,
            "description": event.description,
            "category": event.category,
            "plugin": event.plugin,
            "files": event.files,
            "keys": event.keys,
        }
        if grouped:
            row["count"] = event.count
            row["ids"] = event.ids
        rows[str(index)] = row
    return rows


def undetected_rows(low_timeline: LowLevelTimeline) -> Dict[str, Dict]:
    """Every log line in the output format, analysis fields = "-".

    Sorted like the SigmaDFT output (by date_time_min; an unparseable date
    counts as 1970-01-01, as in MergeHighLevelTimeline.merge).
    """
    default = datetime.fromisoformat("1970-01-01T00:00:00.000000+00:00")

    def when(event):
        try:
            return datetime.fromisoformat(event.date_time_min)
        except (TypeError, ValueError):
            return default

    rows = {}
    for index, event in enumerate(sorted(low_timeline.events, key=when)):
        row = {
            "id": event.id,
            "date_time_min": event.date_time_min,
            "date_time_max": event.date_time_min,
            "evidence_message": event.evidence,
            "plugin": event.plugin,
            "files": event.path,
        }
        row.update({field: NOT_ANALYZED for field in ANALYSIS_FIELDS})
        rows[str(index)] = {field: row[field] for field in FIELDS}
    return rows


def timeline_from_rows(rows: Dict[str, Dict]) -> HighLevelTimeline:
    """Inverse of timeline_rows (detection output read back from JSON), so
    reconstruct() can run later as its own step on a saved detection."""
    timeline = HighLevelTimeline()
    for key in sorted(rows, key=int):
        record = rows[key]
        event = HighLevelEvent()
        for field in FIELDS:
            setattr(event, field, record.get(field))
        event.type_candidate = event.type_candidate or {}
        event.keys = event.keys or {}
        timeline.add_event(event)
    return timeline


def read_rows_json(path: str) -> Dict[str, Dict]:
    with open(path, encoding="utf-8") as file:
        return json.load(file)


@contextmanager
def _output(target, **kwargs):
    """A path is opened for writing; an open text file (e.g. StringIO) is used as is."""
    if isinstance(target, (str, os.PathLike)):
        with open(target, "w", **kwargs) as file:
            yield file
    else:
        yield target


def write_rows_json(rows: Dict[str, Dict], target) -> None:
    with _output(target) as file:
        json.dump(rows, file, indent=4)


def write_rows_csv(rows: Dict[str, Dict], target, grouped: bool = False) -> None:
    """One CSV row per record; dict/list fields (type_candidate, keys, ids)
    are stored as JSON strings, plain strings such as "-" as they are."""
    fieldnames = GROUPED_FIELDS if grouped else FIELDS
    with _output(target, newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for record in rows.values():
            row = dict(record)
            for field in ("type_candidate", "keys", "ids"):
                if field in fieldnames and not isinstance(row.get(field), str):
                    empty = [] if field == "ids" else {}
                    row[field] = json.dumps(row.get(field) or empty, ensure_ascii=False)
            writer.writerow(row)


def write_timeline(timeline: HighLevelTimeline, path: str, grouped: bool = False) -> None:
    """Write a timeline as .json or .csv (chosen from the extension)."""
    rows = timeline_rows(timeline, grouped)
    if Path(path).suffix.lower() == ".csv":
        write_rows_csv(rows, path, grouped)
    else:
        write_rows_json(rows, path)


def _duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    return f"{int(seconds // 60)}m {seconds % 60:.2f}s"

# src/graph2web/cases.py

"""Case pipeline for the web app: upload -> graph -> analysis -> export.

Each step runs as a background job (thread) and uses the same code as the
command line tools:
    import         log2graph (Extractor + GraphWriter), into a new database
    detect         sigmadft.pipeline: rules -> one event per matching log line
    reconstruct    sigmadft.pipeline: adjacent events with the same type -> HLE

Files follow the project layout: an upload is saved as
dataset/uploads/<name>.csv, and results go to the mirrored folder
results/uploads/ with the CLI names (e.g. all_decoded_<name>.json, .csv and
_grouped). The stage of each case is kept in its :Case node.
"""

import csv
import io
import os
import re
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from log2graph import cases, config
from log2graph.cli import read_records
from log2graph.extractor import Extractor
from log2graph.writer import GraphWriter
from sigmadft import pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = PROJECT_ROOT / "dataset"
RESULTS_DIR = PROJECT_ROOT / "results"
UPLOAD_DIR = DATASET_DIR / "uploads"

PLASO_COLUMNS = ["datetime", "timestamp_desc", "source", "source_long", "message",
                 "parser", "display_name", "tag"]
# Neo4j database names: ASCII letters, digits, dots and dashes, at most 63 characters
_NAME_MAX = 63 - len(config.DATABASE_PREFIX)
MAX_LOG_LINES = 300


class CaseError(Exception):
    """A request that cannot be done; status = HTTP status code for the API."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ----------------------------------------------------------------------
# Names, paths and files
# ----------------------------------------------------------------------

def case_slug(name: str) -> str:
    """'My Sample (2).csv' -> 'my-sample-2' (used for the file and the database)."""
    name = re.sub(r"\.csv$", "", name.strip(), flags=re.IGNORECASE).lower()
    name = re.sub(r"[^a-z0-9.]+", "-", name).strip("-.")
    name = re.sub(r"-{2,}", "-", name)[:_NAME_MAX].strip("-.")
    if not name or not name[0].isalnum():
        raise CaseError("The case name needs at least one letter or digit.")
    return name


def database_for(slug: str) -> str:
    return f"{config.DATABASE_PREFIX}{slug}"


def results_dir_for(csv_path: Path) -> Path:
    """results/ mirrors dataset/: dataset/<path>/x.csv -> results/<path>/."""
    try:
        return RESULTS_DIR / csv_path.resolve().parent.relative_to(DATASET_DIR.resolve())
    except ValueError:
        return RESULTS_DIR


def check_plaso_header(path: Path) -> None:
    with open(path, encoding="utf-8-sig", newline="") as f:
        header = next(csv.reader(f), [])
    if [h.strip() for h in header] != PLASO_COLUMNS:
        raise CaseError("Not a Plaso timeline CSV: the header must be "
                        f"'{','.join(PLASO_COLUMNS)}' (found '{','.join(header)[:200]}').")


def count_rows(path: Path) -> int:
    csv.field_size_limit(1000000)
    with open(path, encoding="utf-8", newline="") as f:
        return max(sum(1 for _ in csv.reader(f)) - 1, 0)


# ----------------------------------------------------------------------
# Jobs
# ----------------------------------------------------------------------

class Job:
    def __init__(self, db: str, kind: str, steps: List[str]):
        self.id = uuid.uuid4().hex[:12]
        self.db = db
        self.kind = kind
        self.steps = steps
        self.step = 0
        self.status = "running"     # running | done | error
        self.text = "Starting…"
        self.progress: Optional[float] = None
        self.log: List[str] = []
        self.error: Optional[str] = None
        self.result: Dict[str, Any] = {}
        self.started = time.time()
        self.finished: Optional[float] = None

    def set_step(self, index: int, text: str, progress: Optional[float] = None) -> None:
        self.step, self.text, self.progress = index, text, progress
        self.write(text)

    def write(self, line: str) -> None:
        self.log.append(line)
        if len(self.log) > MAX_LOG_LINES:
            del self.log[: len(self.log) - MAX_LOG_LINES]

    def to_dict(self) -> Dict[str, Any]:
        end = self.finished or time.time()
        return {"id": self.id, "db": self.db, "kind": self.kind, "steps": self.steps,
                "step": self.step, "status": self.status, "text": self.text,
                "progress": self.progress, "error": self.error, "result": self.result,
                "elapsed": round(end - self.started, 1), "log": self.log[-40:]}


_jobs: Dict[str, Job] = {}
_jobs_lock = threading.Lock()


def get_job(job_id: str) -> Job:
    job = _jobs.get(job_id)
    if job is None:
        raise CaseError("Job not found (the server may have restarted).", 404)
    return job


def active_job(db: str) -> Optional[Job]:
    return next((j for j in _jobs.values() if j.db == db and j.status == "running"), None)


def start_job(db: str, kind: str, steps: List[str], work: Callable[[Job], Dict[str, Any]]) -> Job:
    """Run work(job) in a thread; one running job per case."""
    with _jobs_lock:
        running = active_job(db)
        if running:
            raise CaseError(f"'{db}' is busy with another job ({running.kind}).", 409)
        job = Job(db, kind, steps)
        _jobs[job.id] = job

    def run():
        try:
            job.result = work(job) or {}
            job.status, job.progress = "done", 1.0
            job.text = job.result.get("summary", "Done")
        except CaseError as e:
            job.status, job.error = "error", str(e)
        except Exception as e:  # report anything else to the UI instead of losing it
            job.status, job.error = "error", f"{type(e).__name__}: {e}"
            job.write(traceback.format_exc())
        finally:
            job.finished = time.time()
            if job.error:
                job.write(f"Error: {job.error}")

    threading.Thread(target=run, name=f"job-{kind}-{db}", daemon=True).start()
    return job


# ----------------------------------------------------------------------
# Case steps
# ----------------------------------------------------------------------

class Cases:
    """Case operations on one Neo4j connection (conn: uri, user, password)."""

    def __init__(self, conn: Callable[[], Dict[str, str]], driver: Callable[[], Any]):
        self._conn = conn
        self._driver = driver

    def writer(self, db: str) -> GraphWriter:
        c = self._conn()
        return GraphWriter(c["uri"], c["user"], c["password"], db)

    def all_databases(self) -> List[str]:
        with self._driver().session(database="system") as s:
            return [r["name"] for r in s.run("SHOW DATABASES YIELD name RETURN DISTINCT name")]

    def case_info(self, db: str) -> Dict[str, Any]:
        config.check_database_name(db)
        writer = self.writer(db)
        try:
            info = writer.get_case()
        finally:
            writer.close()
        job = active_job(db)
        return {"db": db, "case": info or None, "job": job.to_dict() if job else None}

    def _case(self, writer: GraphWriter) -> Dict[str, Any]:
        info = writer.get_case()
        if not info:
            raise CaseError("This case has no metadata (:Case node). Import it again with log2graph "
                            "or from New case.", 409)
        return info

    # -- 1. upload + import -------------------------------------------------
    async def upload(self, name: str, decode: bool, body) -> Job:
        """Save the uploaded CSV (body: async iterator of bytes), create the
        database and start the import job."""
        slug = case_slug(name)
        db = database_for(slug)
        if db in self.all_databases():
            raise CaseError(f"Case '{db}' already exists. Choose another name.", 409)
        if active_job(db):
            raise CaseError(f"'{db}' is already being imported.", 409)

        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        target = UPLOAD_DIR / f"{slug}.csv"
        part = target.with_suffix(".csv.part")
        size = 0
        try:
            with open(part, "wb") as f:
                async for chunk in body:
                    f.write(chunk)
                    size += len(chunk)
            if size == 0:
                raise CaseError("The uploaded file is empty.")
            check_plaso_header(part)
            part.replace(target)
        finally:
            if part.exists():
                part.unlink()
        return self.start_import(db, target, decode)

    def start_import(self, db: str, csv_path: Path, decode: bool) -> Job:
        steps = ["Create database", "Read log", "Write graph"]

        def work(job: Job) -> Dict[str, Any]:
            job.set_step(0, f"Creating database {db}…")
            with self._driver().session(database="system") as s:
                s.run(f"CREATE DATABASE `{db}` IF NOT EXISTS WAIT 120 SECONDS").consume()
            job.set_step(1, f"Reading {csv_path.name}…")
            extractor = Extractor(config.TEMPLATES_DIR, decode=decode)
            records = read_records(str(csv_path), extractor)
            job.write(f"{len(records)} log lines read")
            job.set_step(2, f"Writing {len(records):,} events to the graph…")
            writer = self.writer(db)
            try:
                if writer.count_nodes():
                    writer.reset()
                writer.ensure_constraints()
                stats = writer.write_records(records)
                writer.set_case(cases.import_props(db, str(csv_path), len(records), decode))
            finally:
                writer.close()
            for key, value in stats.items():
                job.write(f"  {key:<28} {value}")
            return {"summary": f"Imported {len(records):,} log lines", "events": len(records)}

        return start_job(db, "import", steps, work)

    # -- 2. anomaly detection -----------------------------------------------
    def start_detect(self, db: str, rule_source: str) -> Job:
        config.check_database_name(db)
        if rule_source not in pipeline.RULE_SOURCES:
            raise CaseError(f"Unknown rule source '{rule_source}'.")
        steps = ["Read log", "Load rules", "Match rules", "Write results"]

        def work(job: Job) -> Dict[str, Any]:
            writer = self.writer(db)
            try:
                info = self._case(writer)
                csv_path = Path(info["source_csv"])
                if not csv_path.exists():
                    raise CaseError(f"The log file of this case is missing: {csv_path}", 409)
                decode = bool(info.get("decode"))

                job.set_step(0, f"Reading {csv_path.name}{' (decoding payloads)' if decode else ''}…")
                low = pipeline.build_low_timeline(str(csv_path), decode=decode)

                job.set_step(1, f"Loading {rule_source} rules…")
                rules = pipeline.load_rules(rule_source)
                if not rules:
                    raise CaseError("No rule could be loaded.")
                job.write(f"{len(rules)} rules loaded")

                def progress(i, n, title):
                    job.step, job.progress = 2, i / n
                    job.text = f"Matching rule {i}/{n}: {title}"

                job.set_step(2, f"Matching {len(rules)} rules…", 0.0)
                merged = pipeline.detect(low, rules, progress=progress)

                job.set_step(3, "Writing results…")
                out_json = None
                rows: Dict[str, Dict] = {}
                if merged is not None:
                    out_dir = results_dir_for(csv_path)
                    out_dir.mkdir(parents=True, exist_ok=True)
                    stem = pipeline.output_stem(str(csv_path), rule_source, decode)
                    out_json = out_dir / f"{stem}.json"
                    pipeline.write_timeline(merged, str(out_json))
                    pipeline.write_timeline(merged, str(out_dir / f"{stem}.csv"))
                    rows = pipeline.timeline_rows(merged)
                    job.write(f"Saved {out_json} and .csv")
                writer.clear_detection()
                writer.annotate_events(list(rows.values()))
                writer.set_case(cases.detection_props(rule_source, len(rows), str(out_json) if out_json else None))
            finally:
                writer.close()
            return {"summary": f"Detected {len(rows):,} events with {rule_source} rules",
                    "events": len(rows)}

        return start_job(db, "detect", steps, work)

    # -- 3. event reconstruction ---------------------------------------------
    def start_reconstruct(self, db: str) -> Job:
        config.check_database_name(db)
        steps = ["Group events", "Write high-level events"]

        def work(job: Job) -> Dict[str, Any]:
            writer = self.writer(db)
            try:
                info = self._case(writer)
                if info.get("stage") not in ("detected", "reconstructed"):
                    raise CaseError("Run anomaly detection first.", 409)
                job.set_step(0, "Grouping adjacent events with the same type…")
                out = info.get("detection_output")
                rows = pipeline.read_rows_json(out) if out else {}
                grouped = pipeline.reconstruct(pipeline.timeline_from_rows(rows))
                grouped_rows = pipeline.timeline_rows(grouped, grouped=True)
                grouped_json = None
                if out:
                    grouped_json = pipeline.grouped_path(out)
                    pipeline.write_timeline(grouped, grouped_json, grouped=True)
                    pipeline.write_timeline(grouped, str(Path(grouped_json).with_suffix(".csv")), grouped=True)
                    job.write(f"Saved {grouped_json} and .csv")

                job.set_step(1, f"Writing {len(grouped_rows):,} high-level events…")
                writer.clear_hle()
                stats = writer.import_hle(list(grouped_rows.values()))
                writer.set_case(cases.reconstruction_props(len(grouped_rows), grouped_json))
            finally:
                writer.close()
            for key, value in stats.items():
                job.write(f"  {key:<28} {value}")
            return {"summary": f"Built {len(grouped_rows):,} high-level events from {len(rows):,} events",
                    "hle": len(grouped_rows)}

        return start_job(db, "reconstruct", steps, work)

    # -- export -----------------------------------------------------------------
    def export(self, db: str, fmt: str):
        """(filename, text) in the CLI output format of the case's current stage:
        imported -> every log line with '-' analysis fields; detected -> the
        SigmaDFT output; reconstructed -> the grouped output."""
        config.check_database_name(db)
        if fmt not in ("json", "csv"):
            raise CaseError("Format must be json or csv.")
        if active_job(db):
            raise CaseError("Wait until the running job of this case has finished.", 409)
        writer = self.writer(db)
        try:
            info = self._case(writer)
        finally:
            writer.close()
        stage = info.get("stage")
        csv_path = Path(info["source_csv"])
        grouped = False
        if stage == "reconstructed":
            source = info.get("grouped_output")
            rows = pipeline.read_rows_json(source) if source else {}
            stem = Path(source).stem if source else f"{_stem(info, csv_path)}_grouped"
            grouped = True
        elif stage == "detected":
            source = info.get("detection_output")
            rows = pipeline.read_rows_json(source) if source else {}
            stem = Path(source).stem if source else _stem(info, csv_path)
        else:
            if not csv_path.exists():
                raise CaseError(f"The log file of this case is missing: {csv_path}", 409)
            rows = pipeline.undetected_rows(
                pipeline.build_low_timeline(str(csv_path), decode=bool(info.get("decode"))))
            stem = csv_path.stem

        buffer = io.StringIO()
        if fmt == "json":
            pipeline.write_rows_json(rows, buffer)
            # Same bytes as the CLI file: a text-mode file uses the OS line ending
            text = buffer.getvalue().replace("\n", os.linesep)
        else:
            pipeline.write_rows_csv(rows, buffer, grouped=grouped)
            text = buffer.getvalue()
        return f"{stem}.{fmt}", text


def _stem(info: Dict[str, Any], csv_path: Path) -> str:
    return pipeline.output_stem(str(csv_path), info.get("rule_source") or "all", bool(info.get("decode")))

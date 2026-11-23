# src/loggraph/cli.py

"""loggraph CLI: Plaso CSV + SigmaDFT output -> Neo4j graph.

Example:
    PYTHONPATH=src python -m loggraph -i dataset/linux/sample.csv \\
        -d sigmadft-sample -s results/linux/all_decoded_sample.json --reset
"""

import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List

from loggraph import config
from loggraph.extractor import Extractor, GraphRecord


def read_records(csv_path: str, extractor: Extractor) -> List[GraphRecord]:
    """Rows get id = CSV record index (header = 0), same as SigmaDFT ids."""
    csv.field_size_limit(1000000)
    records = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for index, row in enumerate(csv.reader(f)):
            if index > 0:
                records.append(extractor.extract(index, row))
    extractor.link_known_entities(records)
    return records


def load_sigmadft(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return list(data.values()) if isinstance(data, dict) else data


def grouped_path_for(path: str) -> str:
    p = Path(path)
    return str(p.with_name(f"{p.stem}_grouped{p.suffix}"))


def print_stats(title: str, stats: Dict[str, int]) -> None:
    print(title)
    for name, count in stats.items():
        print(f"  {name:<28} {count}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="loggraph", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--input", required=True, help="Plaso timeline CSV")
    parser.add_argument("-d", "--database", help="Neo4j database (must start with 'sigmadft-')")
    parser.add_argument("-s", "--sigmadft", help="SigmaDFT JSON output (per line); its "
                        "<name>_grouped.json is used for high-level events")
    parser.add_argument("-g", "--grouped", help="SigmaDFT grouped JSON (default: derived from -s)")
    parser.add_argument("--reset", action="store_true",
                        help="Delete all nodes of the target database before import")
    parser.add_argument("--no-decode", action="store_true", help="Do not decode payloads")
    parser.add_argument("--dry-run", action="store_true", help="Extract only, do not touch Neo4j")
    parser.add_argument("--templates", default=str(config.TEMPLATES_DIR))
    parser.add_argument("--uri", default=config.NEO4J_URI)
    parser.add_argument("--user", default=config.NEO4J_USER)
    parser.add_argument("--password", default=config.NEO4J_PASSWORD)
    args = parser.parse_args(argv)

    if not args.dry_run:
        if not args.database:
            parser.error("-d/--database is required (unless --dry-run)")
        try:
            config.check_database_name(args.database)
        except ValueError as e:
            parser.error(str(e))

    start = time.time()
    extractor = Extractor(Path(args.templates), decode=not args.no_decode)
    print(f"Templates: {', '.join(t.source for t in extractor.templates)}")
    records = read_records(args.input, extractor)
    print(f"Read {len(records)} rows from {args.input}")
    print_stats("Extracted events:", Counter(":".join(r.labels) for r in records))
    related = [(r.event_id, k, v) for r in records for k, v in r.props.items() if k.startswith("related_")]
    print(f"Known-entity links: {len(related)} events")
    for event_id, prop, values in related:
        print(f"  event {event_id}: {prop} = {values}")
    print_stats("Matched patterns:", Counter(
        f"{r.props['log_type']}/{r.props.get('pattern', '-')}" for r in records))

    sigmadft_events = load_sigmadft(args.sigmadft) if args.sigmadft else None
    grouped_file = args.grouped or (grouped_path_for(args.sigmadft) if args.sigmadft else None)
    grouped_events = load_sigmadft(grouped_file) if grouped_file else None

    if args.dry_run:
        print("Dry run: Neo4j not touched.")
        return 0

    from loggraph.writer import GraphWriter
    writer = GraphWriter(args.uri, args.user, args.password, args.database)
    try:
        existing = writer.count_nodes()
        if existing and not args.reset:
            print(f"Database '{args.database}' already has {existing} nodes; "
                  f"use --reset to replace them.", file=sys.stderr)
            return 1
        if existing:
            print(f"Reset: deleting {existing} nodes from '{args.database}'")
            writer.reset()
        writer.ensure_constraints()
        print_stats(f"Written to '{args.database}':", writer.write_records(records))
        if sigmadft_events is not None:
            print(f"SigmaDFT detections on events: {writer.annotate_events(sigmadft_events)} "
                  f"({args.sigmadft})")
        if grouped_events is not None:
            print_stats(f"High-level events ({grouped_file}):", writer.import_hle(grouped_events))
    finally:
        writer.close()
    print(f"Done in {time.time() - start:.1f} s")
    return 0

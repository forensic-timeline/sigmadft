# src/sigmadft/main.py

import argparse
import os
import time
from datetime import datetime
from pathlib import Path
from typing import List
import sigmadft.analyzers.ReadFromYamlAnalyzer as ReadFromYamlAnalyzer
from sigmadft.reader.CSVReader import CSVReader
from sigmadft.timelines.LowLevelTimeline import LowLevelTimeline
from sigmadft.timelines.HighLevelTimeline import MergeHighLevelTimeline
from sigmadft.output.JSONWriter import JSONWriter
from sigmadft.output.CSVWriter import CSVWriter
from sigmadft.rules.Rule import Rule
from sigmadft.adapters import ADAPTERS, get_adapter


def format_duration(seconds):
    """Format duration in seconds to human-readable format"""
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    else:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.2f}s"


# Main function
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Forensic event reconstruction tool.")
    parser.add_argument(
        "-i",
        "--input_path",
        action="store",
        required=True,
        type=str,
        help="Path to a CSV file from plaso.",
    )
    parser.add_argument(
        "-o",
        "--output_path",
        action="store",
        required=True,
        type=str,
        help="Output file path. Format is chosen from the extension: .json or .csv.",
    )
    parser.add_argument(
        "-s",
        "--rule-source",
        action="store",
        required=False,
        default="atlas",
        choices=list(ADAPTERS) + ["all"],
        help="Rule source to use: atlas (default), sigma, or all.",
    )
    parser.add_argument(
        "-d",
        "--decode",
        action="store_true",
        help="Decode encoded payloads (web query strings, PHP base64_decode) before "
        "matching; decoded text is appended to the message as [DECODED: ...].",
    )

    # Read the arguments from the command line
    args = parser.parse_args()
    input_path = args.input_path
    output_path = args.output_path
    rule_source = args.rule_source

    # Determine output format from the output file extension
    output_format = Path(output_path).suffix.lower().lstrip(".")
    if output_format not in ("json", "csv"):
        parser.error(
            f"Unsupported output extension '{Path(output_path).suffix}'. Use .json or .csv."
        )

    # Start timing the entire process
    total_start_time = time.time()
    start_datetime = datetime.now()

    print(f"[{start_datetime.strftime('%Y-%m-%d %H:%M:%S')}] Starting analysis...")
    print("=" * 60)

    # Read the CSV file
    csv_start_time = time.time()
    print("Reading CSV file ...")
    reader = CSVReader(input_path)
    csv_end_time = time.time()
    print(
        f"  ✓ CSV reading completed in {format_duration(csv_end_time - csv_start_time)}"
    )

    # Create a list of LowLevelEvent objects
    timeline_start_time = time.time()
    print("Creating low-level timeline ...")
    low_timeline = LowLevelTimeline()
    low_timeline.create_timeline(reader, decode=args.decode)
    timeline_end_time = time.time()
    print(
        f"  ✓ Low-level timeline created with {len(low_timeline.events)} events in {format_duration(timeline_end_time - timeline_start_time)}"
    )
    if args.decode:
        print(f"  ✓ Decoded payloads appended to {low_timeline.decoded_count} messages")

    # Create a list of high-level timeline
    high_timelines = []

    # Auto-discover all YAML rules of the selected source(s) via adapters
    rules_dir = os.path.join(os.path.dirname(__file__), "rules")
    sources = list(ADAPTERS) if rule_source == "all" else [rule_source]
    rules = []
    for source in sources:
        adapter = get_adapter(source)
        rules.extend((adapter, path) for path in adapter.discover())
    print(f"Running analysis with rule source '{rule_source}' ({len(rules)} rules)")

    # Read the YAML rules (converted to SigmaDFT Rule objects by the adapter)
    rules_start_time = time.time()
    print("Loading YAML rules ...")
    yaml_contents: List[Rule] = []
    for adapter, yaml_file_path in rules:
        display_path = os.path.relpath(yaml_file_path, rules_dir)

        # Check if rule file exists
        if not os.path.exists(yaml_file_path):
            print(f"Warning: Rule file not found: {yaml_file_path}")
            continue

        try:
            yaml_content = adapter.load(yaml_file_path)
            yaml_content.rule_file = display_path.replace(os.sep, "/")
            yaml_contents.append(yaml_content)
            print(f"  ✓ Loaded rule [{adapter.name}]: {display_path}")
        except Exception as e:
            print(f"  ✗ Error loading rule [{adapter.name}] {display_path}: {str(e)}")
            continue

    rules_end_time = time.time()
    print(
        f"  ✓ Loaded {len(yaml_contents)} rules in {format_duration(rules_end_time - rules_start_time)}"
    )

    if not yaml_contents:
        print("Error: No valid rules could be loaded. Exiting.")
        return

    # Run each rules with the analyzer
    analysis_start_time = time.time()
    print(f"Running {len(yaml_contents)} rules against the timeline...")
    total_events_found = 0

    for i, yaml_content in enumerate(yaml_contents, 1):
        rule_start_time = time.time()
        print(f"[{i}/{len(yaml_contents)}] Processing rule: {yaml_content.title} ...")

        try:
            high_timeline = ReadFromYamlAnalyzer.Run(low_timeline, yaml_content)
            rule_end_time = time.time()

            if high_timeline and len(high_timeline.events) > 0:
                high_timelines.append(high_timeline)
                events_count = len(high_timeline.events)
                total_events_found += events_count
                print(
                    f"  ✓ Found {events_count} events in {format_duration(rule_end_time - rule_start_time)}"
                )
            else:
                print(
                    f"  ○ No events found in {format_duration(rule_end_time - rule_start_time)}"
                )
        except Exception as e:
            rule_end_time = time.time()
            print(
                f"  ✗ Error processing rule in {format_duration(rule_end_time - rule_start_time)}: {str(e)}"
            )
            continue

    analysis_end_time = time.time()
    print(
        f"  ✓ Rule analysis completed in {format_duration(analysis_end_time - analysis_start_time)}"
    )
    print(f"  ✓ Total events found: {total_events_found}")

    if not high_timelines:
        print("No events were detected by any rules.")
        total_end_time = time.time()
        print(
            f"\nTotal execution time: {format_duration(total_end_time - total_start_time)}"
        )
        return

    # Merge the high-level timelines
    merge_start_time = time.time()
    print("Merging high-level timelines ...")
    merge_timelines = MergeHighLevelTimeline(high_timelines)
    merged_high_timelines = merge_timelines.merge()
    merge_end_time = time.time()
    print(
        f"  ✓ Timeline merging completed in {format_duration(merge_end_time - merge_start_time)}"
    )

    # Write the results to a JSON or CSV file (based on output extension)
    output_start_time = time.time()
    format_label = output_format.upper()
    print(f"Writing results to {format_label} file: {output_path} ...")
    print(f"Total events in merged timeline: {len(merged_high_timelines.events)}")
    writer_class = CSVWriter if output_format == "csv" else JSONWriter
    writer_class(merged_high_timelines, output_path).write()

    # Grouped version (always written): adjacent events with the same type
    # become one event (first event + ids/count), saved as <name>_grouped.<ext>
    grouped_high_timelines = MergeHighLevelTimeline.group_consecutive_by_type(merged_high_timelines)
    output_file = Path(output_path)
    grouped_output_path = str(output_file.with_name(f"{output_file.stem}_grouped{output_file.suffix}"))
    print(f"Writing grouped results to {format_label} file: {grouped_output_path} ...")
    print(f"Total events in grouped timeline: {len(grouped_high_timelines.events)}")
    writer_class(grouped_high_timelines, grouped_output_path, grouped=True).write()
    output_end_time = time.time()
    print(
        f"  ✓ {format_label} output completed in {format_duration(output_end_time - output_start_time)}"
    )

    # Calculate and display total execution time
    total_end_time = time.time()
    total_duration = total_end_time - total_start_time
    end_datetime = datetime.now()

    print("=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Start time:          {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"End time:            {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total duration:      {format_duration(total_duration)}")
    print(f"Input events:        {len(low_timeline.events):,}")
    print(f"Rules processed:     {len(yaml_contents)}")
    print(f"Output events:       {len(merged_high_timelines.events):,}")
    print(
        f"Processing rate:     {len(low_timeline.events) / total_duration:.0f} events/second"
    )
    print("=" * 60)
    print("Analysis completed successfully!")
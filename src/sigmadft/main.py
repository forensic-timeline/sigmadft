# src/sigmadft/main.py

import argparse
import time
from datetime import datetime
from pathlib import Path

from sigmadft import pipeline


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


# Main function (the steps themselves live in sigmadft/pipeline.py, shared with the web app)
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
        choices=pipeline.RULE_SOURCES,
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

    # Read the CSV file and create the low-level timeline
    timeline_start_time = time.time()
    print("Creating low-level timeline ...")
    low_timeline = pipeline.build_low_timeline(input_path, decode=args.decode)
    timeline_end_time = time.time()
    print(
        f"  ✓ Low-level timeline created with {len(low_timeline.events)} events in {format_duration(timeline_end_time - timeline_start_time)}"
    )
    if args.decode:
        print(f"  ✓ Decoded payloads appended to {low_timeline.decoded_count} messages")

    # Read the YAML rules of the selected source(s) (converted to Rule objects by the adapters)
    rules_start_time = time.time()
    rules = pipeline.load_rules(rule_source, log=print)
    rules_end_time = time.time()
    print(
        f"  ✓ Loaded {len(rules)} rules in {format_duration(rules_end_time - rules_start_time)}"
    )

    if not rules:
        print("Error: No valid rules could be loaded. Exiting.")
        return

    # Anomaly detection: run each rule, merge to one event per log line
    analysis_start_time = time.time()
    print(f"Running {len(rules)} rules against the timeline...")
    merged_high_timelines = pipeline.detect(low_timeline, rules, log=print)
    analysis_end_time = time.time()
    print(
        f"  ✓ Rule analysis and merging completed in {format_duration(analysis_end_time - analysis_start_time)}"
    )

    if merged_high_timelines is None:
        print("No events were detected by any rules.")
        total_end_time = time.time()
        print(
            f"\nTotal execution time: {format_duration(total_end_time - total_start_time)}"
        )
        return

    # Write the results to a JSON or CSV file (based on output extension)
    output_start_time = time.time()
    format_label = output_format.upper()
    print(f"Writing results to {format_label} file: {output_path} ...")
    print(f"Total events in merged timeline: {len(merged_high_timelines.events)}")
    pipeline.write_timeline(merged_high_timelines, output_path)

    # Event reconstruction (grouped version, always written): adjacent events with
    # the same type become one event (first event + ids/count), saved as <name>_grouped.<ext>
    grouped_high_timelines = pipeline.reconstruct(merged_high_timelines)
    grouped_output_path = pipeline.grouped_path(output_path)
    print(f"Writing grouped results to {format_label} file: {grouped_output_path} ...")
    print(f"Total events in grouped timeline: {len(grouped_high_timelines.events)}")
    pipeline.write_timeline(grouped_high_timelines, grouped_output_path, grouped=True)
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
    print(f"Rules processed:     {len(rules)}")
    print(f"Output events:       {len(merged_high_timelines.events):,}")
    print(
        f"Processing rate:     {len(low_timeline.events) / total_duration:.0f} events/second"
    )
    print("=" * 60)
    print("Analysis completed successfully!")

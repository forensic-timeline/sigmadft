# src/sigmadft/output/CSVWriter.py

import csv
import json
from sigmadft.timelines.HighLevelTimeline import HighLevelTimeline
from sigmadft.output.JSONWriter import JSONWriter


class CSVWriter:
    def __init__(self, timeline: HighLevelTimeline, csv_path: str):
        """Initializes the CSVWriter class"""
        self.timeline = timeline
        self.csv_path = csv_path

    def write(self):
        """Writes the timeline to a CSV file (one row per high-level event).

        Columns follow the JSON output fields; 'keys' is stored as a single
        JSON string column.
        """
        timeline_dict = JSONWriter(self.timeline, self.csv_path).to_dict()
        fieldnames = [
            'id', 'date_time_min', 'date_time_max', 'evidence_source', 'type',
            'description', 'category', 'plugin', 'files', 'keys',
        ]

        with open(self.csv_path, 'w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for event in timeline_dict.values():
                row = dict(event)
                row['keys'] = json.dumps(event.get('keys') or {}, ensure_ascii=False)
                writer.writerow(row)

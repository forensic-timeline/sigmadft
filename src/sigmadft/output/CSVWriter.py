# src/sigmadft/output/CSVWriter.py

from sigmadft.timelines.HighLevelTimeline import HighLevelTimeline


class CSVWriter:
    def __init__(self, timeline: HighLevelTimeline, csv_path: str, grouped: bool = False):
        """Initializes the CSVWriter class (grouped: also write ids and count)"""
        self.timeline = timeline
        self.csv_path = csv_path
        self.grouped = grouped

    def write(self):
        """Writes the timeline to a CSV file (one row per high-level event).

        Columns follow the JSON output fields; 'type_candidate', 'keys' (and
        'ids' when grouped) are stored as JSON string columns.
        """
        from sigmadft.pipeline import timeline_rows, write_rows_csv
        write_rows_csv(timeline_rows(self.timeline, self.grouped), self.csv_path, self.grouped)

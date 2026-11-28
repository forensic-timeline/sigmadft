# src/sigmadft//output/JSONWriter.py

from sigmadft.timelines.HighLevelTimeline import HighLevelTimeline


class JSONWriter:
    def __init__(self, timeline: HighLevelTimeline, json_path: str, grouped: bool = False):
        """Initializes the JSONWriter class (grouped: also write ids and count)"""
        self.timeline = timeline
        self.json_path = json_path
        self.grouped = grouped

    def to_dict(self) -> dict:
        """Converts the timeline (list) to a dictionary (see pipeline.timeline_rows).

        'supporting' and 'trigger' are not written (disabled on purpose).
        """
        from sigmadft.pipeline import timeline_rows
        return timeline_rows(self.timeline, self.grouped)

    def write(self):
        """Writes the timeline to a JSON file"""
        from sigmadft.pipeline import write_rows_json
        write_rows_json(self.to_dict(), self.json_path)

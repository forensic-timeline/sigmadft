# src/sigmadft//output/JSONWriter.py

import json
from sigmadft.timelines.HighLevelTimeline import HighLevelTimeline


class JSONWriter:
    def __init__(self, timeline: HighLevelTimeline, json_path: str, grouped: bool = False):
        """Initializes the JSONWriter class (grouped: also write ids and count)"""
        self.timeline = timeline.events
        self.json_path = json_path
        self.grouped = grouped

    def to_dict(self) -> dict:
        """Converts the timeline (list) to a dictionary"""
        timeline_dict = {}
        for index, event in enumerate(self.timeline):
            timeline_dict[index] = {
                'id': event.id,
                'date_time_min': event.date_time_min,
                'date_time_max': event.date_time_max,
                'evidence_message': event.evidence_message,
                'type_candidate': event.type_candidate,
                'type': event.type,
                'description': event.description,
                'category': event.category,
                'plugin': event.plugin,
                'files': event.files,
                'keys': event.keys,
                **({'count': event.count, 'ids': event.ids} if self.grouped else {}),
                # Dinonaktifkan: 'supporting' dan 'trigger' tidak ditulis ke output
                # 'supporting': event.supporting,
                # 'trigger': event.trigger.to_dict() if event.trigger else None,
            }
        
        return timeline_dict

    def write(self):
        """Writes the timeline to a JSON file"""
        timeline_dict = self.to_dict()
        
        with open(self.json_path, 'w') as file:
            json.dump(timeline_dict, file, indent=4)
        
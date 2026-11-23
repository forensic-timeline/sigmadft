# src/sigmadft/timelines/HighLevelTimeline.py

import copy
from datetime import datetime
from typing import Any, Dict, List
from sigmadft.events.HighLevelEvent import HighLevelEvent

# Rule level priority for choosing the primary event (unknown/None = 0)
LEVEL_RANK = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


class HighLevelTimeline:
    """A class to represent a high-level timeline of events"""
    
    def __init__(self):
        """Initialize the HighLevelTimeline object"""
        self.events: List[HighLevelEvent] = []
    
    def add_event(self, event: HighLevelEvent):
        """Add a HighLevelEvent object to the HighLevelTimeline object"""
        self.events.append(event)
    
    def add_events(self, events: list[HighLevelEvent]):
        """Add a list of HighLevelEvent objects to the HighLevelTimeline object"""
        self.events.extend(events)

    def get_indexes_of_events_between_datetimes(self, start_datetime: datetime, end_datetime: datetime) -> list[int]:
        """Get the indexes of events that fall between the start and end datetimes"""

        # Initialize an empty list to store the indexes of events 
        indexes = []

        # Iterate through the events and check if the date_time_min and date_time_max fall between the start and end datetimes
        for i, event in enumerate(self.events):
            # Compare the date_time_min and date_time_max with the start and end datetimes
            if datetime.fromisoformat(event.date_time_min) >= start_datetime and datetime.fromisoformat(event.date_time_max) <= end_datetime:
                indexes.append(i)
        
        return indexes
    
    def intersect_with(self, index: int, indexes: list[int]) -> bool:
        """Check if the event at the given index intersects with any of the events in the list of indexes"""
        
        # Initialize a flag to indicate if the events have been merged
        merged = False

        for i in indexes:
            # Check if the events match exactly
            if self.exact_match(self.events[index], self.events[i]):
                print("Merging events: ", self.events[index].evidence_message, " and ", self.events[i].evidence_message)
                self.events[index].merge(self.events[i].id)
                merged = True
        
        return merged

    def exact_match(self, event: HighLevelEvent, another_event: HighLevelEvent) -> bool:
        """Tries to match a test event with the current event and returns true if they match exactly. We do not check id, date_time_min, date_time_max, trigger, supporting, merged_id"""
        
        if event.evidence_message != another_event.evidence_message:
            return False
        if event.type != another_event.type:
            return False
        if event.description != another_event.description:
            return False
        if event.category != another_event.category:
            return False
        if event.device != another_event.device:
            return False
        if event.files != another_event.files:
            return False
        if event.keys != another_event.keys:
            return False
        
        return True


class MergeHighLevelTimeline:
    """A class to merge multiple HighLevelTimeline objects into a single HighLevelTimeline object"""

    def __init__(self, high_timelines: HighLevelTimeline):
        """Initialize the MergeHighLevelTimeline object with a list of HighLevelTimeline objects"""
        self.high_timelines = high_timelines
    
    def merge(self) -> HighLevelTimeline:
        """Merge the HighLevelTimeline objects into a single HighLevelTimeline object"""

        # Initialize an empty list to combine all lists
        merged_timeline = []
        
        # Use extend method in a for loop to combine lists
        for high_timeline in self.high_timelines:
            merged_timeline.extend(high_timeline.events)

        # One high-level event per log line: events are grouped by id (the
        # input CSV row), all matching rules go to type_candidate
        merged_timeline = self.merge_by_id(merged_timeline)

        # Convert date_time_min to datetime objects for sorting
        # Handle invalid dates (like year 0000) by using a default date
        default_date = datetime.fromisoformat("1970-01-01T00:00:00.000000+00:00")
        
        for event in merged_timeline:
            try:
                # Try to parse the date
                event.date_time_iso = datetime.fromisoformat(event.date_time_min)
            except ValueError as _:
                # If the date is invalid (like year 0000), use the default date
                # print(f"Warning: Invalid date format in event {event.id}: {event.date_time_min}. Using default date.")
                event.date_time_iso = default_date
                # Optionally update the event's date strings to the default
                event.date_time_min = "1970-01-01T00:00:00.000000+00:00"
                if event.date_time_max:
                    event.date_time_max = "1970-01-01T00:00:00.000000+00:00"
        
        # Sort the combined list by the date_time_obj key
        merged_timeline.sort(key=lambda x: x.date_time_iso)
        
        # Create a new HighLevelTimeline object to store the merged timeline
        merged_high_timeline = HighLevelTimeline()
        merged_high_timeline.add_events(merged_timeline)

        return merged_high_timeline

    @staticmethod
    def merge_by_id(events: List[HighLevelEvent]) -> List[HighLevelEvent]:
        """Merge events of the same log line (same id) into one event.

        The primary event (its type, description, category, keys) is the one
        whose rule has the highest level; on a tie, the rule processed first
        (atlas before sigma, then sorted rule path). type_candidate lists every
        matching rule in processing order, keyed by rule file.
        """
        groups: Dict[Any, List[HighLevelEvent]] = {}
        for event in events:
            groups.setdefault(event.id, []).append(event)

        merged = []
        for group in groups.values():
            primary = max(
                enumerate(group),
                key=lambda item: (LEVEL_RANK.get(item[1].rule_level, 0), -item[0]),
            )[1]
            primary.type_candidate = {
                event.rule_file: {
                    "type": event.rule_type,
                    "source": event.rule_source,
                    "level": event.rule_level,
                }
                for event in group
            }
            merged.append(primary)

        return merged

    @staticmethod
    def group_consecutive_by_type(timeline: HighLevelTimeline) -> HighLevelTimeline:
        """Group adjacent events (in output order) that have the same type.

        Each group becomes one event copied from its first event (id,
        evidence_message, keys, description, type_candidate, ...), with
        date_time_max taken from the last event, plus ids (all member ids)
        and count. The input timeline is not modified.
        """
        grouped_timeline = HighLevelTimeline()
        current = None
        for event in timeline.events:
            if current is not None and event.type == current.type:
                current.ids.append(event.id)
                current.count += 1
                current.date_time_max = event.date_time_max
                continue
            current = copy.copy(event)
            current.ids = [event.id]
            current.count = 1
            grouped_timeline.add_event(current)
        return grouped_timeline

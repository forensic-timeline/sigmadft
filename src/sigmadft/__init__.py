# src/sigmadft/__init__.py

"""
SigmaDFT - Digital Forensics Timeline Analysis using Sigma-like rules
"""

__version__ = "1.0.0"
__author__ = "Java Kanaya Prada"
__email__ = "javakanaya@gmail.com"

# Import main classes for easy access
from .timelines.LowLevelTimeline import LowLevelTimeline
from .timelines.HighLevelTimeline import HighLevelTimeline
from .events.LowLevelEvent import LowLevelEvent
from .events.HighLevelEvent import HighLevelEvent
from .rules.Rule import Rule

__all__ = [
    "LowLevelTimeline",
    "HighLevelTimeline", 
    "LowLevelEvent",
    "HighLevelEvent",
    "Rule",
]
# src/log2graph/config.py

"""Neo4j connection settings and graph constants for log2graph.

Connection values can be overridden with environment variables
(LOG2GRAPH_NEO4J_URI, LOG2GRAPH_NEO4J_USER, LOG2GRAPH_NEO4J_PASSWORD) or CLI
options. The defaults are the user's local Neo4j instance.
"""

import os
from pathlib import Path

NEO4J_URI = os.environ.get("LOG2GRAPH_NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("LOG2GRAPH_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("LOG2GRAPH_NEO4J_PASSWORD", "adminkami")

# Only databases with this prefix may be read or written by log2graph
DATABASE_PREFIX = "sigmadft-"

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Entity node label -> unique key property (MERGE key + uniqueness constraint)
ENTITY_KEYS = {
    "IPAddress": "ip",
    "User": "username",
    "Page": "path",
    "UserAgent": "value",
    "Service": "name",
    "LogFile": "path",
}

# Event sub-labels allowed in templates (every event also gets :Event)
EVENT_LABELS = {"HTTPRequest", "AuthEvent", "SystemEvent"}

BATCH_SIZE = 1000


def check_database_name(name: str) -> None:
    """Refuse any database outside this project (prefix 'sigmadft-')."""
    if not name.startswith(DATABASE_PREFIX) or len(name) <= len(DATABASE_PREFIX):
        raise ValueError(
            f"Database '{name}' is not allowed: log2graph only uses databases "
            f"named '{DATABASE_PREFIX}<dataset>'."
        )

# src/loggraph/writer.py

"""Write loggraph records and SigmaDFT high-level events to Neo4j.

All queries run on one database whose name must start with 'sigmadft-'
(checked in __init__). Labels and relation types are inserted into Cypher
text only after validation against config / templates.
"""

import json
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List

from neo4j import GraphDatabase

from loggraph.config import BATCH_SIZE, ENTITY_KEYS, check_database_name
from loggraph.extractor import GraphRecord

NODE_KEYS = {"Event": "event_id", "HighLevelEvent": "hle_id", **ENTITY_KEYS}


def _batches(rows: List[Any], size: int = BATCH_SIZE) -> Iterable[List[Any]]:
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


def _iso_or_none(value: str):
    """Plaso datetime string if parseable (Cypher datetime()), else None."""
    try:
        datetime.fromisoformat(value)
        return value
    except (TypeError, ValueError):
        return None


class GraphWriter:
    def __init__(self, uri: str, user: str, password: str, database: str):
        check_database_name(database)
        self.database = database
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.driver.verify_connectivity()
        with self.driver.session(database="system") as session:
            found = session.run("SHOW DATABASES YIELD name WHERE name = $name RETURN name",
                                name=database).single()
        if not found:
            self.driver.close()
            raise ValueError(f"Database '{database}' does not exist in Neo4j (create it first).")

    def close(self):
        self.driver.close()

    def _run(self, query: str, **params):
        with self.driver.session(database=self.database) as session:
            return session.run(query, **params).consume()

    def _rows(self, query: str, rows: List[Any], **params) -> None:
        for batch in _batches(rows):
            self._run(query, rows=batch, **params)

    # ------------------------------------------------------------------
    # Database state
    # ------------------------------------------------------------------
    def count_nodes(self) -> int:
        with self.driver.session(database=self.database) as session:
            return session.run("MATCH (n) RETURN count(n) AS c").single()["c"]

    def reset(self) -> None:
        """Delete every node/relation of THIS database (prefix-checked)."""
        self._run("MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS")

    def ensure_constraints(self) -> None:
        for label, key in NODE_KEYS.items():
            name = f"loggraph_{label.lower()}_{key}"
            self._run(f"CREATE CONSTRAINT {name} IF NOT EXISTS "
                      f"FOR (n:{label}) REQUIRE n.{key} IS UNIQUE")

    # ------------------------------------------------------------------
    # Low-level events and entities
    # ------------------------------------------------------------------
    def write_records(self, records: List[GraphRecord]) -> Dict[str, int]:
        stats: Dict[str, int] = defaultdict(int)

        # Event nodes, grouped by label combination
        by_labels: Dict[tuple, List[Dict]] = defaultdict(list)
        for rec in records:
            by_labels[tuple(rec.labels)].append(
                {"props": rec.props, "ts": _iso_or_none(rec.props.get("datetime"))})
        for labels, rows in by_labels.items():
            self._rows(
                f"UNWIND $rows AS row CREATE (e:{':'.join(labels)}) SET e = row.props, "
                "e.timestamp = CASE WHEN row.ts IS NULL THEN null ELSE datetime(row.ts) END",
                rows)
            stats[":".join(labels)] += len(rows)

        # Entity nodes
        entities: Dict[str, set] = defaultdict(set)
        for rec in records:
            for start, _, end in rec.relations:
                for label, value in (start, end):
                    if label in ENTITY_KEYS:
                        entities[label].add(value)
        for label, values in entities.items():
            key = ENTITY_KEYS[label]
            self._rows(f"UNWIND $rows AS v MERGE (:{label} {{{key}: v}})", sorted(values, key=str))
            stats[label] = len(values)

        # Relations, grouped by (start label, type, end label)
        by_rel: Dict[tuple, List[Dict]] = defaultdict(list)
        for rec in records:
            for (sl, sv), rel_type, (el, ev) in rec.relations:
                by_rel[(sl, rel_type, el)].append({"s": sv, "e": ev})
        for (sl, rel_type, el), rows in by_rel.items():
            self._rows(
                f"UNWIND $rows AS r MATCH (a:{sl} {{{NODE_KEYS[sl]}: r.s}}) "
                f"MATCH (b:{el} {{{NODE_KEYS[el]}: r.e}}) MERGE (a)-[:{rel_type}]->(b)",
                rows)
            stats[f"[:{rel_type}]"] += len(rows)

        # Temporal order of all events
        ordered = sorted(records, key=lambda r: (r.props.get("datetime") or "", r.event_id))
        pairs = [{"s": a.event_id, "e": b.event_id} for a, b in zip(ordered, ordered[1:])]
        self._rows("UNWIND $rows AS r MATCH (a:Event {event_id: r.s}) "
                   "MATCH (b:Event {event_id: r.e}) MERGE (a)-[:NEXT]->(b)", pairs)
        stats["[:NEXT]"] = len(pairs)
        return dict(stats)

    # ------------------------------------------------------------------
    # SigmaDFT results
    # ------------------------------------------------------------------
    def annotate_events(self, sigmadft_events: List[Dict]) -> int:
        """Copy per-line SigmaDFT detections onto Event nodes (+ :Detected)."""
        rows = [{
            "id": int(ev["id"]),
            "type": ev.get("type"),
            "category": ev.get("category"),
            "description": ev.get("description"),
            "type_candidate": json.dumps(ev.get("type_candidate") or {}, ensure_ascii=False),
        } for ev in sigmadft_events]
        self._rows(
            "UNWIND $rows AS r MATCH (e:Event {event_id: r.id}) SET e:Detected, "
            "e.sigmadft_type = r.type, e.sigmadft_category = r.category, "
            "e.sigmadft_description = r.description, e.sigmadft_type_candidate = r.type_candidate",
            rows)
        return len(rows)

    def import_hle(self, grouped_events: List[Dict]) -> Dict[str, int]:
        """High-level events from SigmaDFT grouped output (option a: as-is)."""
        rows = []
        for seq, ev in enumerate(grouped_events):
            keys = ev.get("keys") or {}
            props = {
                "hle_id": int(ev["id"]),
                "seq": seq,
                "type": ev.get("type"),
                "category": ev.get("category"),
                "description": ev.get("description"),
                "count": ev.get("count", 1),
                "ids": [int(i) for i in ev.get("ids") or [ev["id"]]],
                "date_time_min": ev.get("date_time_min"),
                "date_time_max": ev.get("date_time_max"),
                "evidence_message": ev.get("evidence_message"),
                "plugin": ev.get("plugin"),
                "files": ev.get("files"),
                "keys": json.dumps(keys, ensure_ascii=False),
                "type_candidate": json.dumps(ev.get("type_candidate") or {}, ensure_ascii=False),
            }
            # Flattened keys for querying, e.g. h.key_Source_IP
            for name, value in keys.items():
                if isinstance(value, (str, int, float, bool)) and value != "":
                    props[f"key_{name}"] = value
            rows.append({
                "props": props,
                "ts_min": _iso_or_none(props["date_time_min"]),
                "ts_max": _iso_or_none(props["date_time_max"]),
            })

        self._rows(
            "UNWIND $rows AS row CREATE (h:HighLevelEvent) SET h = row.props, "
            "h.timestamp_min = CASE WHEN row.ts_min IS NULL THEN null ELSE datetime(row.ts_min) END, "
            "h.timestamp_max = CASE WHEN row.ts_max IS NULL THEN null ELSE datetime(row.ts_max) END",
            rows)
        self._rows(
            "UNWIND $rows AS row MATCH (h:HighLevelEvent {hle_id: row.props.hle_id}) "
            "UNWIND row.props.ids AS id MATCH (e:Event {event_id: id}) MERGE (h)-[:CONTAINS]->(e)",
            rows)
        pairs = [{"s": a["props"]["hle_id"], "e": b["props"]["hle_id"]} for a, b in zip(rows, rows[1:])]
        self._rows(
            "UNWIND $rows AS r MATCH (a:HighLevelEvent {hle_id: r.s}) "
            "MATCH (b:HighLevelEvent {hle_id: r.e}) MERGE (a)-[:FOLLOWED_BY]->(b)",
            pairs)
        multi_actor = self.set_actors()

        with self.driver.session(database=self.database) as session:
            contains = session.run("MATCH (:HighLevelEvent)-[r:CONTAINS]->() RETURN count(r) AS c").single()["c"]
        return {"HighLevelEvent": len(rows), "  with >1 actor": multi_actor,
                "[:CONTAINS]": contains, "[:FOLLOWED_BY]": len(pairs)}

    def set_actors(self) -> int:
        """Store the actors of each HLE as properties (no HLE -> entity relation).

        One HLE node may have several actors. Actor = entity that performs a
        member event: IPAddress via REQUEST / CONNECT, User via PERFORMED
        (targets such as RUN_AS or RELATED_TO users are not actors).
        Properties: actor_ips, actor_users (sorted lists), actor_count, and
        actor_details (JSON string: per actor event_ids, first_seen, last_seen).
        Returns the number of HLEs with more than one actor.
        """
        actors: Dict[int, Dict[tuple, Dict]] = defaultdict(dict)
        with self.driver.session(database=self.database) as session:
            result = session.run(
                "MATCH (h:HighLevelEvent)-[:CONTAINS]->(e:Event)<-[:REQUEST|CONNECT|PERFORMED]-(a) "
                "WHERE a:IPAddress OR a:User "
                "RETURN h.hle_id AS hle, CASE WHEN a:IPAddress THEN 'ip' ELSE 'user' END AS kind, "
                "       coalesce(a.ip, a.username) AS value, e.event_id AS id, e.datetime AS dt")
            for r in result:
                entry = actors[r["hle"]].setdefault(
                    (r["kind"], r["value"]),
                    {"kind": r["kind"], "value": r["value"], "event_ids": set(), "datetimes": []})
                entry["event_ids"].add(r["id"])
                entry["datetimes"].append(r["dt"])

        with self.driver.session(database=self.database) as session:
            hle_ids = [r["h"] for r in session.run("MATCH (h:HighLevelEvent) RETURN h.hle_id AS h")]
        rows = []
        for hle_id in hle_ids:
            details = []
            for (kind, value), entry in sorted(actors.get(hle_id, {}).items()):
                datetimes = sorted(d for d in entry["datetimes"] if d)
                details.append({
                    "kind": kind, "value": value,
                    "event_ids": sorted(entry["event_ids"]),
                    "event_count": len(entry["event_ids"]),
                    "first_seen": datetimes[0] if datetimes else None,
                    "last_seen": datetimes[-1] if datetimes else None,
                })
            rows.append({
                "hle": hle_id,
                "ips": [d["value"] for d in details if d["kind"] == "ip"],
                "users": [d["value"] for d in details if d["kind"] == "user"],
                "details": json.dumps(details, ensure_ascii=False),
            })
        self._rows(
            "UNWIND $rows AS r MATCH (h:HighLevelEvent {hle_id: r.hle}) "
            "SET h.actor_ips = r.ips, h.actor_users = r.users, "
            "    h.actor_count = size(r.ips) + size(r.users), h.actor_details = r.details",
            rows)
        return sum(1 for r in rows if len(r["ips"]) + len(r["users"]) > 1)

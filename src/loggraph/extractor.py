# src/loggraph/extractor.py

"""Turn Plaso CSV rows into graph records using YAML extraction templates.

A template (templates/*.yaml) declares which rows it handles (`detect`), the
fields to extract (template-level `fields` for every row, plus `patterns`
tried in order, first match wins) and the relations between the event and
entity nodes. No Cypher lives in templates: the writer builds it.

Field spec forms inside a pattern:
    name: 2                                  # regex group
    name: {group: 5, transform: int}         # group + transform
    name: {value: sudo}                      # constant
Template-level fields are `name: <regex>` (group 1).

Relation spec: {from: <end>, type: REL, to: <end>} where <end> is `event`
or `{Label: field}` (entity node keyed by the field value). Relations whose
entity field is empty are skipped.

Known-entity relation spec (template level `known_entity_relations`):
{field: decoded_payload, type: RELATED_TO, to: User}. After all rows are
extracted, every token of the field that equals the key of an entity seen
in any row (e.g. a username from auth.log) gives event -[:RELATED_TO]-> it;
no new entity node is created (Extractor.link_known_entities).
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from loggraph.config import ENTITY_KEYS, EVENT_LABELS

# Plaso CSV columns
COLUMNS = ["datetime", "timestamp_desc", "source", "source_long",
           "message", "parser", "display_name", "tag"]

_REL_TYPE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _strip_query(value: str) -> str:
    return value.split("?", 1)[0]


TRANSFORMS = {
    "int": lambda v: int(v),
    "lower": lambda v: v.lower(),
    "strip_query": _strip_query,
    "session": lambda v: f"session_{v.lower()}",
}


def normalize_log_file(display_name: str) -> str:
    """'OS:evidences\\\\\\\\apache2\\\\x.log' -> 'evidences/apache2/x.log'"""
    path = display_name[3:] if display_name.startswith("OS:") else display_name
    return re.sub(r"[\\/]+", "/", path)


@dataclass
class Endpoint:
    """Relation end: the row's event (label None) or an entity node."""
    label: Optional[str]
    field: Optional[str] = None

    @classmethod
    def parse(cls, spec: Any, where: str) -> "Endpoint":
        if spec == "event":
            return cls(None)
        if isinstance(spec, dict) and len(spec) == 1:
            label, fld = next(iter(spec.items()))
            if label not in ENTITY_KEYS:
                raise ValueError(f"{where}: unknown entity label '{label}'")
            return cls(label, fld)
        raise ValueError(f"{where}: invalid relation end {spec!r}")


@dataclass
class RelationSpec:
    start: Endpoint
    type: str
    end: Endpoint


def _parse_relations(specs: List[Dict], where: str) -> List[RelationSpec]:
    relations = []
    for spec in specs or []:
        rel_type = spec.get("type", "")
        if not _REL_TYPE.match(rel_type):
            raise ValueError(f"{where}: invalid relation type '{rel_type}'")
        relations.append(RelationSpec(Endpoint.parse(spec.get("from"), where),
                                      rel_type,
                                      Endpoint.parse(spec.get("to"), where)))
    return relations


@dataclass
class KnownEntitySpec:
    field: str
    type: str
    label: str


def _parse_known(specs: List[Dict], where: str) -> List[KnownEntitySpec]:
    known = []
    for spec in specs or []:
        rel_type, label = spec.get("type", ""), spec.get("to", "")
        if not _REL_TYPE.match(rel_type):
            raise ValueError(f"{where}: invalid relation type '{rel_type}'")
        if label not in ENTITY_KEYS:
            raise ValueError(f"{where}: unknown entity label '{label}'")
        known.append(KnownEntitySpec(spec.get("field", ""), rel_type, label))
    return known


_TOKEN_SPLIT = re.compile(r"[\s'\"`;,()\[\]{}=]+")


def payload_tokens(value: Any) -> set:
    """Tokens of a payload: items of a JSON list (if it is one), each also
    split on whitespace/quotes/punctuation. ["-u", "phopkins"] -> {-u, phopkins}"""
    items = [value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                items = [str(x) for x in parsed]
        except ValueError:
            pass
    tokens = set()
    for item in items:
        item = str(item)
        tokens.add(item.strip())
        tokens.update(t for t in _TOKEN_SPLIT.split(item) if t)
    tokens.discard("")
    return tokens


@dataclass
class Pattern:
    name: str
    regex: re.Pattern
    fields: Dict[str, Any]
    relations: List[RelationSpec]

    def extract(self, message: str) -> Optional[Dict[str, Any]]:
        match = self.regex.search(message)
        if not match:
            return None
        values: Dict[str, Any] = {}
        for name, spec in self.fields.items():
            if isinstance(spec, int):
                spec = {"group": spec}
            if "value" in spec:
                value = spec["value"]
            else:
                value = match.group(spec["group"])
                if value is not None and "transform" in spec:
                    value = TRANSFORMS[spec["transform"]](value)
            if value not in (None, ""):
                values[name] = value
        return values


@dataclass
class Template:
    log_type: str
    order: int
    event_label: str
    fallback_label: str
    parsers: List[str]
    filenames: List[str]
    fields: Dict[str, re.Pattern]
    relations: List[RelationSpec]
    patterns: List[Pattern]
    known: List[KnownEntitySpec] = field(default_factory=list)
    source: str = ""

    @classmethod
    def load(cls, path: Path) -> "Template":
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        where = path.name
        event_label = data.get("event_label", "SystemEvent")
        fallback_label = data.get("fallback_label", event_label)
        for label in (event_label, fallback_label):
            if label not in EVENT_LABELS:
                raise ValueError(f"{where}: unknown event label '{label}'")
        detect = data.get("detect") or {}
        patterns = [
            Pattern(name, re.compile(p["regex"]), p.get("fields") or {},
                    _parse_relations(p.get("relations"), f"{where}:{name}"))
            for name, p in (data.get("patterns") or {}).items()
        ]
        return cls(
            log_type=data["log_type"],
            order=int(data.get("order", 100)),
            event_label=event_label,
            fallback_label=fallback_label,
            parsers=detect.get("parser_equals") or [],
            filenames=[f.lower() for f in detect.get("filename_contains") or []],
            fields={k: re.compile(v) for k, v in (data.get("fields") or {}).items()},
            relations=_parse_relations(data.get("relations"), where),
            patterns=patterns,
            known=_parse_known(data.get("known_entity_relations"), where),
            source=where,
        )

    def detects(self, parser: str, log_file: str) -> bool:
        name = log_file.lower()
        return parser in self.parsers or any(f in name for f in self.filenames)


@dataclass
class GraphRecord:
    """One CSV row: the event node plus its entity relations."""
    event_id: int
    labels: List[str]                     # e.g. ["Event", "HTTPRequest"]
    props: Dict[str, Any]
    # (start, rel_type, end); an end is ("Event", event_id) or (Label, key value)
    relations: List[Tuple[Tuple[str, Any], str, Tuple[str, Any]]] = field(default_factory=list)
    # Known-entity relations to resolve once all rows are read
    known: List[KnownEntitySpec] = field(default_factory=list)


class Extractor:
    def __init__(self, templates_dir: Path, decode: bool = True):
        self.templates = sorted(
            (Template.load(p) for p in Path(templates_dir).glob("*.yaml")),
            key=lambda t: (t.order, t.source),
        )
        self.decode = None
        if decode:
            # Same decoder as `sigmadft -d` (fills decoded_payload)
            from sigmadft.utils.log_decoder import decode_payload
            self.decode = decode_payload

    def extract(self, event_id: int, row: List[str]) -> GraphRecord:
        raw = dict(zip(COLUMNS, row + [""] * (len(COLUMNS) - len(row))))
        log_file = normalize_log_file(raw["display_name"])
        props: Dict[str, Any] = {
            "event_id": event_id,
            **raw,
            "log_file": log_file,
            "log_type": "unknown",
        }
        if self.decode:
            decoded = self.decode(raw["message"])
            if decoded:
                props["decoded_payload"] = decoded

        labels = ["Event"]
        relations: List[RelationSpec] = []
        known: List[KnownEntitySpec] = []
        values: Dict[str, Any] = {}

        template = next((t for t in self.templates
                         if t.detects(raw["parser"], log_file)), None)
        if template:
            props["log_type"] = template.log_type
            for name, regex in template.fields.items():
                match = regex.search(raw["message"])
                if match and match.group(1):
                    values[name] = match.group(1)
            relations.extend(template.relations)
            known = template.known
            label = template.fallback_label
            for pattern in template.patterns:
                found = pattern.extract(raw["message"])
                if found is not None:
                    props["pattern"] = pattern.name
                    values.update(found)
                    relations.extend(pattern.relations)
                    label = template.event_label
                    break
            labels.append(label)
        props.update(values)

        record = GraphRecord(event_id, labels, props, known=known)
        record.relations.append((("Event", event_id), "FROM_FILE", ("LogFile", log_file)))
        for rel in relations:
            start = self._end(rel.start, event_id, values)
            end = self._end(rel.end, event_id, values)
            if start and end:
                record.relations.append((start, rel.type, end))
        return record

    @staticmethod
    def _end(endpoint: Endpoint, event_id: int, values: Dict[str, Any]):
        if endpoint.label is None:
            return ("Event", event_id)
        value = values.get(endpoint.field)
        return (endpoint.label, value) if value not in (None, "") else None

    @staticmethod
    def link_known_entities(records: List[GraphRecord]) -> int:
        """Resolve known-entity relations (see module docstring); returns count.

        The matched keys are also stored on the event as `related_<label>`
        (e.g. related_user = ["phopkins"]).
        """
        known_keys: Dict[str, set] = {}
        for rec in records:
            for start, _, end in rec.relations:
                for label, value in (start, end):
                    if label in ENTITY_KEYS:
                        known_keys.setdefault(label, set()).add(str(value))
        added = 0
        for rec in records:
            for spec in rec.known:
                value = rec.props.get(spec.field)
                if value in (None, ""):
                    continue
                matches = sorted(payload_tokens(value) & known_keys.get(spec.label, set()))
                for key in matches:
                    rec.relations.append((("Event", rec.event_id), spec.type, (spec.label, key)))
                    added += 1
                if matches:
                    prop = f"related_{spec.label.lower()}"
                    rec.props[prop] = sorted(set(rec.props.get(prop, [])) | set(matches))
        return added

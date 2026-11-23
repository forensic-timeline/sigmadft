# src/sigmadft/rules/Rule.py

import re
from dataclasses import dataclass, field
from datetime import datetime, date
from typing import List, Dict, Any, Optional, Union, Callable
from enum import Enum

class RuleStatus(Enum):
    """Valid status values for rules"""
    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"
    
class RuleLevel(Enum):
    """Valid level values for rules"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    

@dataclass
class DetectionDefinition:
    """Represents the detection configuration in a rule"""

    keywords: Union[List[str], Dict[str, List[str]]]
    condition: str = "keywords"
    modifiers: List[str] = field(default_factory=list)
    # Optional compiled matcher (set by non-atlas adapters, e.g. SigmaAdapter).
    # When present it replaces keyword matching: matcher(event_text) -> bool.
    matcher: Optional[Callable[[str], bool]] = field(default=None, repr=False, compare=False)

    # Keyword groups (keywords_group_1, ...) combined by `condition`; empty for
    # rules with a single `keywords` entry
    groups: Dict[str, "KeywordGroup"] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionDefinition":
        if not isinstance(data, dict):
            raise ValueError("Detection definition must be a dictionary")

        condition = data.get("condition", "keywords")
        group_names = [name for name in data if name != "condition"]

        # Several keyword groups: compile `condition` into a matcher
        if group_names and group_names != ["keywords"]:
            groups = {name: KeywordGroup.from_value(data[name]) for name in group_names}
            evaluate = compile_condition(condition, groups)
            return cls(
                keywords=[],
                condition=condition,
                groups=groups,
                matcher=lambda text: evaluate(lambda name: groups[name].matches(text)),
            )

        keywords_data, modifiers = _split_modifiers(data.get("keywords", []))
        return cls(
            keywords=keywords_data,
            condition=condition,
            modifiers=modifiers,
        )
        
    def validate(self) -> List[str]:
        """Validate the detection configuration"""
        errors = []

        # Validate keywords
        if not self.keywords and not self.groups:
            errors.append("At least one keyword is required")

        # Validate modifiers
        modifiers = list(self.modifiers)
        for group in self.groups.values():
            modifiers.extend(group.modifiers)
        for modifier in modifiers:
            if modifier not in VALID_MODIFIERS:
                errors.append(f"Invalid modifier: {modifier}")

        return errors


VALID_MODIFIERS = {"all", "re"}


def _split_modifiers(value: Any):
    """Split a keywords value into (keywords, modifiers).

    The value is a list of keywords, a single keyword, or a dict keyed by the
    modifiers, e.g. {'|all|re': [...]}.
    """
    modifiers: List[str] = []
    if isinstance(value, dict):
        modifier_key = next(iter(value))
        if modifier_key.startswith("|"):
            modifiers = [m for m in modifier_key.split("|") if m]
            value = value[modifier_key]
    if isinstance(value, str):
        value = [value]
    return value or [], modifiers


@dataclass
class KeywordGroup:
    """One keyword group (keywords_group_N) of a detection.

    Matching is the same as a single `keywords` entry: substring, or regex
    (re.search) with the `re` modifier; any keyword, or every keyword with
    the `all` modifier.
    """

    keywords: List[str]
    modifiers: List[str] = field(default_factory=list)
    patterns: List[Any] = field(default_factory=list, repr=False, compare=False)

    @classmethod
    def from_value(cls, value: Any) -> "KeywordGroup":
        keywords, modifiers = _split_modifiers(value)
        keywords = [str(k) for k in keywords]
        if not keywords:
            raise ValueError("A keyword group needs at least one keyword")
        patterns: List[Any] = keywords
        if "re" in modifiers:
            patterns = [re.compile(k) for k in keywords]
        return cls(keywords=keywords, modifiers=modifiers, patterns=patterns)

    def matches(self, text: str) -> bool:
        if "re" in self.modifiers:
            results = (p.search(text) is not None for p in self.patterns)
        else:
            results = (k in text for k in self.patterns)
        return all(results) if "all" in self.modifiers else any(results)


_CONDITION_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)")


def compile_condition(condition: str, groups: Dict[str, Any]) -> Callable[[Callable[[str], bool]], bool]:
    """Compile a condition such as 'keywords_group_1 and (keywords_group_2 or
    keywords_group_3)' into evaluate(group_matches) -> bool.

    Operators: and, or, not, parentheses (precedence not > and > or).
    group_matches(name) is only called for the groups that are needed.
    """
    if not isinstance(condition, str) or not condition.strip():
        raise ValueError("Detection condition is required")

    tokens = []
    position = 0
    text = condition.strip()
    while position < len(text):
        match = _CONDITION_TOKEN.match(text, position)
        if not match:
            raise ValueError(f"Invalid condition syntax at '{text[position:]}'")
        tokens.append(match.group(1))
        position = match.end()
        while position < len(text) and text[position].isspace():
            position += 1

    index = 0

    def peek():
        return tokens[index] if index < len(tokens) else None

    def take():
        nonlocal index
        token = peek()
        index += 1
        return token

    def parse_or():
        node = parse_and()
        while peek() == "or":
            take()
            left, right = node, parse_and()
            node = lambda m, l=left, r=right: l(m) or r(m)
        return node

    def parse_and():
        node = parse_not()
        while peek() == "and":
            take()
            left, right = node, parse_not()
            node = lambda m, l=left, r=right: l(m) and r(m)
        return node

    def parse_not():
        if peek() == "not":
            take()
            operand = parse_not()
            return lambda m, o=operand: not o(m)
        return parse_atom()

    def parse_atom():
        token = take()
        if token == "(":
            node = parse_or()
            if take() != ")":
                raise ValueError(f"Missing ')' in condition '{condition}'")
            return node
        if token is None or token in ("and", "or", "not", ")"):
            raise ValueError(f"Unexpected '{token}' in condition '{condition}'")
        if token not in groups:
            raise ValueError(f"Condition refers to unknown keyword group '{token}'")
        return lambda m, name=token: m(name)

    evaluate = parse_or()
    if index != len(tokens):
        raise ValueError(f"Unexpected '{tokens[index]}' in condition '{condition}'")
    return evaluate


@dataclass
class KeyDefinition:
    """Defines a key in the high-level event configuration"""
    name: str
    source: str  # Name of the utility function to call

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyDefinition":
        return cls(
            name=data.get("name", ""),
            source=data.get("source", "")
        )


@dataclass
class HighLevelEventDefinition:
    """Defines the structure of a high-level event in the rule"""

    type: str
    description: str
    keys: List[KeyDefinition]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HighLevelEventDefinition":
        return cls(
            type=data.get("type", ""),
            description=data.get("description", ""),
            keys=[KeyDefinition.from_dict(k) for k in data.get("keys", [])],
        )


@dataclass
class ReasoningDefinition:
    """Defines the reasoning section in the rule"""
    description: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReasoningDefinition":
        return cls(
            description=data.get("description", ""), 
        )


@dataclass
class Rule:
    """Represents a detection rule with all its components"""

    title: str
    id: str
    description: str
    category: str
    detection: DetectionDefinition
    high_level_event: Optional[HighLevelEventDefinition] = None
    reasoning: Optional[ReasoningDefinition] = None
    status: RuleStatus = field(default=RuleStatus.EXPERIMENTAL)
    level: RuleLevel = field(default=RuleLevel.INFORMATIONAL)
    author: Optional[str] = None
    date: Optional[datetime] = None
    modified: Optional[datetime] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    is_sigma_rule: bool = field(default=False)
    # Rule source / adapter name ("atlas", "sigma")
    source: str = field(default="atlas")
    # Rule file path relative to src/sigmadft/rules/ (forward slashes), set in main.py
    rule_file: str = field(default="")
    # Optional per-event key selector (Sigma adapter): event -> List[KeyDefinition]
    key_selector: Optional[Callable[[Any], List[KeyDefinition]]] = field(default=None, repr=False)

    @classmethod
    def from_yaml(cls, yaml_data: Dict) -> "Rule":
        # Parse dates if they exist
        date_obj = None
        if "date" in yaml_data:
            if isinstance(yaml_data["date"], (datetime, date)):
                # Already a datetime object
                date_obj = yaml_data["date"]
            else:
                # Try to parse from string
                try:
                    date_obj = datetime.strptime(yaml_data["date"], "%Y/%m/%d")
                except ValueError:
                    try:
                        date_obj = datetime.strptime(yaml_data["date"], "%Y-%m-%d")
                    except ValueError:
                        pass

        # Similar modification for 'modified' field
        modified_obj = None
        if "modified" in yaml_data:
            if isinstance(yaml_data["modified"], (datetime, date)):
                # Already a datetime object
                modified_obj = yaml_data["modified"]
            else:
                # Try to parse from string
                try:
                    modified_obj = datetime.strptime(yaml_data["modified"], "%Y/%m/%d")
                except ValueError:
                    try:
                        modified_obj = datetime.strptime(yaml_data["modified"], "%Y-%m-%d")
                    except ValueError:
                        pass
                        

        # Parse detection configuration
        detection_data = yaml_data.get("detection", {})
        detection = DetectionDefinition.from_dict(detection_data)

        # Determine if this is a Sigma rule or a custom event reconstruction rule
        is_sigma_rule = "high_level_event" not in yaml_data
        
        # Parse high level event definition if available
        high_level_event = None
        if "high_level_event" in yaml_data:
            high_level_event_data = yaml_data.get("high_level_event", {})
            high_level_event = HighLevelEventDefinition.from_dict(high_level_event_data)

        # Parse reasoning if it exists
        reasoning = None
        if "reasoning" in yaml_data:
            reasoning_data = yaml_data.get("reasoning")
            reasoning = ReasoningDefinition.from_dict(reasoning_data) if reasoning_data else None

        # Create the rule
        rule = cls(
            title=yaml_data.get("title", ""),
            id=yaml_data.get("id", ""),
            description=yaml_data.get("description", ""),
            category=yaml_data.get("category", "Unknown"),
            detection=detection,
            high_level_event=high_level_event,
            reasoning=reasoning,
            status=yaml_data.get("status", "experimental"),
            level=yaml_data.get("level"),
            author=yaml_data.get("author"),
            date=date_obj,
            modified=modified_obj,
            references=yaml_data.get("references", []),
            tags=yaml_data.get("tags", []),
            is_sigma_rule=is_sigma_rule
        )
        
        return rule

    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary"""
        detection_dict = {
            "keywords": self.detection.keywords,
            "condition": self.detection.condition
        }
        
        # Keyword groups combined by condition
        if self.detection.groups:
            detection_dict = {
                name: (
                    {'|' + '|'.join(group.modifiers): group.keywords}
                    if group.modifiers else group.keywords
                )
                for name, group in self.detection.groups.items()
            }
            detection_dict["condition"] = self.detection.condition
        # Add modifiers if present
        elif self.detection.modifiers:
            modifier_key = '|' + '|'.join(self.detection.modifiers)
            detection_dict = {
                "keywords": {
                    modifier_key: self.detection.keywords
                },
                "condition": self.detection.condition
            }
        
        result = {
            "title": self.title,
            "id": self.id,
            "description": self.description,
            "category": self.category,
            "status": self.status,
            "author": self.author,
            "date": self.date.strftime("%Y/%m/%d") if self.date else None,
            "modified": self.modified.strftime("%Y/%m/%d") if self.modified else None,
            "references": self.references,
            "tags": self.tags,
            "detection": detection_dict,
        }
        
        # Add high_level_event if available
        if self.high_level_event:
            result["high_level_event"] = {
                "type": self.high_level_event.type,
                "description": self.high_level_event.description,
                "keys": [
                    {
                        "name": k.name,
                        "source": k.source
                    }
                    for k in self.high_level_event.keys
                ],
            }
            
        # Add reasoning if available
        if self.reasoning:
            result["reasoning"] = {
                "description": self.reasoning.description,
                "found_in": self.reasoning.found_in,
            }
            
        return result
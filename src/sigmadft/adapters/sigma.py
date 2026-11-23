# src/sigmadft/adapters/sigma.py

"""Adapter for SigmaHQ-style rules (https://github.com/SigmaHQ/sigma).

Rules are parsed with pySigma (condition parsing, modifiers, `1 of` / `all of`
expansion are handled by the library). The parsed condition tree is then
compiled into a Python matcher that runs against the same per-row text that
SigmaDFT already uses for atlas rules:

    "{timestamp_desc}-{source} {message} {source}-{source_long}-{parser}"

Field mapping is LOOSE: a Plaso CSV row has no structured fields (Image,
CommandLine, cs-uri-query, ...), so field names are ignored and every value
is searched anywhere in the row text. Consequences:
  - Exact values and `|startswith` / `|endswith` are searched anywhere, but
    the anchored side must be on a token boundary (not glued to [A-Za-z0-9_-]).
  - A value may match text that belongs to a different "field".
  - `field: ''` and `field: null` cannot be evaluated and never match.
  - `?` and `*` in plain values are Sigma wildcards (escape with `\\`).
String matching follows Sigma semantics (case-insensitive unless `|cased`).
"""

import ipaddress
import re
from typing import Callable, List, Optional

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from sigmadft.adapters.base import RuleAdapter
from sigmadft.rules.Rule import DetectionDefinition, KeyDefinition, Rule

Matcher = Callable[[str], bool]

# Characters treated as part of a token for exact/startswith/endswith boundaries
_WORD_CHAR = re.compile(r"[A-Za-z0-9_\-]")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}")


class UnsupportedSigmaFeature(Exception):
    pass


def _never(_: str) -> bool:
    return False


def _string_matcher(value: SigmaString, keyword: bool = False) -> Matcher:
    tokens = list(value.s)
    if not tokens:
        # Exact empty value (e.g. `c-useragent: ''`): emptiness of a field
        # cannot be proven from free text.
        return _never
    # Loose mapping: the value may appear anywhere in the row. Leading/trailing
    # `*` (from contains/startswith/endswith) are dropped; a side WITHOUT `*`
    # (exact match, startswith, endswith) must sit on a token boundary, so that
    # short exact values such as 'M', 'x' or '_' do not match inside other
    # tokens (token chars: [A-Za-z0-9_-]).
    # Keywords (no field) are full-text search: plain contains, no anchoring.
    anchored_left = not keyword and tokens[0] != SpecialChars.WILDCARD_MULTI
    anchored_right = not keyword and tokens[-1] != SpecialChars.WILDCARD_MULTI
    while tokens and tokens[0] == SpecialChars.WILDCARD_MULTI:
        tokens.pop(0)
    while tokens and tokens[-1] == SpecialChars.WILDCARD_MULTI:
        tokens.pop()
    parts = []
    for part in tokens:
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        else:  # placeholder (%name%): unknown value, accept anything
            parts.append(".*")
    pattern = "".join(parts)
    if not pattern:  # value was only wildcards (`*`): any value
        return lambda text: True
    if anchored_left and isinstance(tokens[0], str) and _WORD_CHAR.match(tokens[0][:1]):
        pattern = r"(?<![A-Za-z0-9_\-])" + pattern
    if anchored_right and isinstance(tokens[-1], str) and _WORD_CHAR.match(tokens[-1][-1:]):
        pattern = pattern + r"(?![A-Za-z0-9_\-])"
    flags = re.DOTALL if isinstance(value, SigmaCasedString) else re.DOTALL | re.IGNORECASE
    regex = re.compile(pattern, flags)
    return lambda text: regex.search(text) is not None


def _regex_matcher(value: SigmaRegularExpression) -> Matcher:
    flags = 0
    for flag in value.flags:
        flags |= value.sigma_to_python_flags[flag]
    regex = re.compile(str(value.regexp), flags)
    return lambda text: regex.search(text) is not None


def _cidr_matcher(value: SigmaCIDRExpression) -> Matcher:
    network = value.network
    finder = _IPV4_RE if network.version == 4 else _IPV6_RE

    def match(text: str) -> bool:
        for candidate in finder.findall(text):
            try:
                if ipaddress.ip_address(candidate) in network:
                    return True
            except ValueError:
                continue
        return False

    return match


def _value_matcher(value, keyword: bool = False) -> Matcher:
    if isinstance(value, SigmaString):  # includes SigmaCasedString
        return _string_matcher(value, keyword)
    if isinstance(value, SigmaRegularExpression):
        return _regex_matcher(value)
    if isinstance(value, SigmaNumber):
        regex = re.compile(rf"(?<!\d){re.escape(str(value.number))}(?!\d)")
        return lambda text: regex.search(text) is not None
    if isinstance(value, SigmaCIDRExpression):
        return _cidr_matcher(value)
    if isinstance(value, SigmaExpansion):
        subs = [_value_matcher(v, keyword) for v in value.values]
        return lambda text: any(m(text) for m in subs)
    if isinstance(value, SigmaNull):
        return _never
    raise UnsupportedSigmaFeature(f"value type {type(value).__name__}")


def _compile(node) -> Matcher:
    if isinstance(node, ConditionAND):
        subs = [_compile(a) for a in node.args]
        return lambda text: all(m(text) for m in subs)
    if isinstance(node, ConditionOR):
        subs = [_compile(a) for a in node.args]
        return lambda text: any(m(text) for m in subs)
    if isinstance(node, ConditionNOT):
        sub = _compile(node.args[0])
        return lambda text: not sub(text)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        # Field name is ignored: loose mapping.
        return _value_matcher(node.value)
    if isinstance(node, ConditionValueExpression):  # keyword search
        return _value_matcher(node.value, keyword=True)
    raise UnsupportedSigmaFeature(f"condition node {type(node).__name__}")


def build_matcher(sigma_rule: SigmaRule) -> Matcher:
    """Compile all conditions of a Sigma rule into one matcher (conditions are OR-ed)."""
    matchers = [_compile(c.parsed) for c in sigma_rule.detection.parsed_condition]
    if len(matchers) == 1:
        return matchers[0]
    return lambda text: any(m(text) for m in matchers)


# ----------------------------------------------------------------------
# Generic keys
# ----------------------------------------------------------------------
# Sigma rules have no high_level_event, so keys are chosen per EVENT (one
# Sigma rule may match lines from different logs) from the Plaso parser,
# falling back to the source file path (display_name). Sources are extractor
# functions in utils/util.py, as for atlas rules.

WEB_KEYS = [
    KeyDefinition("Request_URI", "extract_http_request_uri"),
    KeyDefinition("HTTP_Method", "extract_webshell_http_method"),
    KeyDefinition("Source_IP", "extract_webshell_source_ip"),
    KeyDefinition("Response_Code", "extract_webshell_response_code"),
    KeyDefinition("User_Agent", "extract_webshell_user_agent"),
]

AUTH_KEYS = [
    KeyDefinition("Target_User", "extract_generic_target_user"),
    KeyDefinition("Source_IP", "extract_auth_source_ip"),
    KeyDefinition("Service", "extract_auth_service"),
]

_WEB_PARSERS = ("text/apache_access",)
_WEB_FILES = ("access.log", "access_log")
_AUTH_PARSERS = ("text/syslog", "text/syslog_traditional", "systemd_journal")
_AUTH_FILES = ("auth.log", "syslog")


def select_generic_keys(low_level_event) -> List[KeyDefinition]:
    """Pick the generic key profile for an event (web, auth/syslog, or none)."""
    # plugin = "{source}-{source_long}-{parser}" (LowLevelTimeline)
    parser = (getattr(low_level_event, "plugin", "") or "").rsplit("-", 1)[-1]
    path = (getattr(low_level_event, "path", "") or "").lower()
    if parser in _WEB_PARSERS or any(f in path for f in _WEB_FILES):
        return WEB_KEYS
    if parser in _AUTH_PARSERS or any(f in path for f in _AUTH_FILES):
        return AUTH_KEYS
    return []


def _category(sigma_rule: SigmaRule) -> str:
    ls = sigma_rule.logsource
    return ls.category or ls.service or ls.product or "Unknown"


def _level(sigma_rule: SigmaRule) -> Optional[str]:
    return sigma_rule.level.name.lower() if sigma_rule.level else None


def _status(sigma_rule: SigmaRule) -> str:
    return sigma_rule.status.name.lower() if sigma_rule.status else "experimental"


class SigmaAdapter(RuleAdapter):
    """SigmaHQ rules stored in src/sigmadft/rules/sigma/."""

    name = "sigma"
    rules_subdir = "sigma"

    def load(self, file_path: str) -> Rule:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()

        # collect_errors: tolerate metadata issues (non-namespaced tags,
        # non-UUID id) that do not affect detection.
        sigma_rule = SigmaRule.from_yaml(text, collect_errors=True)
        matcher = build_matcher(sigma_rule)

        return Rule(
            title=sigma_rule.title or "",
            id=str(sigma_rule.id) if sigma_rule.id else "",
            description=(sigma_rule.description or "").strip(),
            category=_category(sigma_rule),
            detection=DetectionDefinition(keywords=[], matcher=matcher),
            status=_status(sigma_rule),
            level=_level(sigma_rule),
            author=sigma_rule.author,
            date=sigma_rule.date,
            modified=sigma_rule.modified,
            references=list(sigma_rule.references or []),
            tags=[str(t) for t in (sigma_rule.tags or [])],
            is_sigma_rule=True,
            source=self.name,
            key_selector=select_generic_keys,
        )

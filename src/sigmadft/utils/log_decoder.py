# src/sigmadft/utils/log_decoder.py
"""Decode encoded payloads in log messages before rule matching (-d/--decode).

Logic follows reconsgat's process/log_decoder.py
(https://github.com/forensic-timeline/reconsgat/blob/main/process/log_decoder.py):

1. PHP path (any log): base64 inside ``base64_decode("...")``.
2. Web path (Apache access log lines with ``http_request:`` and a query
   string): the first ``name=value`` of the request query is decoded with
   several methods (URL, hex, base64, base64+decompress, ROT13, single-byte
   XOR). Unlike reconsgat, no user-agent condition is required.

Every decoded candidate is scored by the number of distinct shell command
keywords it contains; the best candidate is kept only if its score > 0 and is
appended to the message as ``original [DECODED: text]`` (the original text is
never replaced). Lines with nothing decodable are returned unchanged.
"""

import base64
import binascii
import codecs
import gzip
import json
import re
import zlib
from typing import List, Optional, Tuple
from urllib.parse import unquote_plus

# Command keywords used for scoring (reconsgat list; its missing comma that
# merged "ss" and "docker" into "ssdocker" is fixed here)
COMMAND_KEYWORDS = [
    "id", "whoami", "uname", "date", "cal", "uptime", "who", "w", "last",
    "finger", "lsb_release", "clear", "netstat", "ip", "ifconfig", "ss",
    "netcat", "ls", "find", "chmod", "chown", "rm", "mv", "echo", "base64",
    "dir", "cp", "cd", "cat", "head", "tail", "less", "more", "strings",
    "wget", "curl", "fetch", "ps", "top", "tmux", "screen", "mysql", "psql",
    "pgsql", "mongo", "redis-cli", "tar", "zip", "unzip", "7z", "rar", "bash",
    "sh", ".sh", "perl", "python", "python3", "php", "ruby", "lua", "gcc",
    "nc", "socat", "ssh", "nmap", "masscan", "tcpdump", "wireshark", "tshark",
    "ettercap", "dsniff", "iptables", "ufw", "firewalld", "hydra", "medusa",
    "john", "hashcat", "gdb", "strace", "ltrace", "systemctl", "service",
    "init.d", "rc.d", "pwd", "dpkg", "docker", "kubectl", "helm", "git",
    "svn", "hg", "df", "timedatectl", "lastlog", "history", "watch", "reset",
]
# A keyword matches only when not glued to [a-z0-9] on either side
_KEYWORD_PATTERNS = [
    re.compile(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])")
    for k in dict.fromkeys(COMMAND_KEYWORDS)
]

_XOR_MARKERS = ("<?php", "eval(", "system", "exec")
_PHP_B64_RE = re.compile(
    r"base64_decode\(\s*(?:\\\\|\\)?['\"]([A-Za-z0-9+/=]+)(?:\\\\|\\)?['\"]\s*\)"
)
_REQUEST_RE = re.compile(r"http_request:\s+[A-Z]+\s+(\S+)")
_QUERY_PARAM_RE = re.compile(r"[?&]([^=\s]+)=([^&\s]+)")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")


def keyword_score(text: str) -> int:
    """Number of distinct command keywords in text (JSON lists are joined)."""
    lowered = text.lower()
    try:
        parsed = json.loads(lowered)
        if isinstance(parsed, list):
            lowered = " ".join(str(item) for item in parsed)
    except ValueError:
        pass
    return sum(1 for pattern in _KEYWORD_PATTERNS if pattern.search(lowered))


def _b64_bytes(value: str) -> Optional[bytes]:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None


def _decompress(data: bytes) -> Optional[bytes]:
    for decompress in (gzip.decompress, zlib.decompress,
                       lambda d: zlib.decompress(d, -zlib.MAX_WBITS)):
        try:
            return decompress(data)
        except Exception:
            continue
    return None


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def decode_candidates(value: str) -> List[Tuple[str, str]]:
    """All (method, decoded_text) candidates for one encoded value."""
    candidates = []

    unquoted = unquote_plus(value)
    if unquoted != value:
        candidates.append(("url-unquote", unquoted))

    is_hex = (len(unquoted) >= 8 and len(unquoted) % 2 == 0
              and _HEX_RE.fullmatch(unquoted) is not None)
    if is_hex:
        candidates.append(("hex", _text(bytes.fromhex(unquoted))))

    raw = _b64_bytes(unquoted)
    if raw:
        candidates.append(("base64", _text(raw)))
        decompressed = _decompress(raw)
        if decompressed:
            candidates.append(("base64+decompress", _text(decompressed)))

    candidates.append(("rot13", codecs.decode(unquoted, "rot13")))

    if is_hex:
        data = bytes.fromhex(unquoted)
        for key in range(1, 256):
            text = _text(bytes(b ^ key for b in data))
            if any(marker in text for marker in _XOR_MARKERS):
                candidates.append((f"single-byte-xor-key={key}", text))
                break

    return candidates


def choose_best(candidates: List[Tuple[str, str]]) -> Optional[str]:
    """Best candidate text by keyword score, or None if no candidate scores > 0."""
    scored = [(keyword_score(text), text) for _, text in candidates]
    if not scored:
        return None
    # Highest score first, shorter text first on a tie (stable sort)
    scored.sort(key=lambda item: (-item[0], len(item[1])))
    top_score = scored[0][0]
    if top_score <= 0:
        return None

    def bonus(text: str) -> int:
        value = 0
        if text.startswith(("[", "{")) or '"' in text or "'" in text:
            value += 1
        if any(ord(ch) < 32 for ch in text[:50]):
            value -= 1
        return value

    best = [text for score, text in scored if score == top_score]
    best.sort(key=bonus, reverse=True)
    return best[0]


def _decode_php(message: str) -> Optional[str]:
    for encoded in _PHP_B64_RE.findall(message):
        raw = _b64_bytes(encoded)
        if raw:
            text = _text(raw)
            return text if keyword_score(text) > 0 else None
    return None


def _decode_web_query(message: str) -> Optional[str]:
    if "http_request:" not in message:
        return None
    request = _REQUEST_RE.search(message)
    if not request or "?" not in request.group(1):
        return None
    param = _QUERY_PARAM_RE.search(request.group(1))
    if not param:
        return None
    return choose_best(decode_candidates(param.group(2)))


def decode_payload(message: str) -> Optional[str]:
    """Decoded payload text of a message (single line), or None if nothing decodes."""
    if not message:
        return None
    decoded = _decode_php(message) or _decode_web_query(message)
    if decoded is None:
        return None
    return " ".join(decoded.split())  # keep the message on a single line


def decode_message(message: str) -> str:
    """Return ``message [DECODED: text]`` if a payload decodes to commands, else message."""
    decoded = decode_payload(message)
    return message if decoded is None else f"{message} [DECODED: {decoded}]"

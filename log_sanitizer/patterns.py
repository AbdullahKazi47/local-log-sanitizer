"""Built-in redaction rules for common kinds of sensitive data."""

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class Rule:
    """A named regex whose matches (or one named group of them) get redacted.

    ``group`` selects the part of the match to replace; ``validator`` can
    reject regex hits that are not real matches (e.g. ``12:34:56`` for IPv6).
    """

    name: str
    regex: re.Pattern
    group: int | str = 0
    validator: Optional[Callable[[str], bool]] = None

    @property
    def placeholder(self) -> str:
        return f"[REDACTED_{self.name.upper()}]"


def _is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

EMAIL = Rule(
    "email",
    re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
)

# Broad candidate pattern; the validator decides whether it is really IPv6.
IPV6 = Rule(
    "ipv6",
    re.compile(
        r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
        rf"(?:{_OCTET}(?:\.{_OCTET}){{3}}|[0-9A-Fa-f]{{0,4}})(?![\w:])"
    ),
    validator=_is_ipv6,
)

IPV4 = Rule(
    "ipv4",
    re.compile(rf"(?<![\w.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\.?\d)(?!\w)"),
)

# key=value / key: value style secrets; only the value is redacted.
SECRET_ASSIGNMENT = Rule(
    "secret",
    re.compile(
        r"(?i)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|"
        r"access[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|pwd)"
        r"\b[\"']?\s*[:=]\s*[\"']?(?!\[REDACTED_)(?P<value>[^\s\"',;&]{6,})"
    ),
    group="value",
)

BEARER = Rule(
    "secret",
    re.compile(r"(?i)\bbearer\s+(?P<value>[A-Za-z0-9\-._~+/]{8,}=*)"),
    group="value",
)

# Well-known token prefixes (cloud keys, chat and code hosting tokens, etc.).
PREFIXED_TOKEN = Rule(
    "secret",
    re.compile(
        r"\b(?:AKIA[0-9A-Z]{16}|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|"
        r"sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abpr]-[A-Za-z0-9-]{10,})\b"
    ),
)

# Long opaque strings mixing letters and digits look like generated secrets.
GENERIC_TOKEN = Rule(
    "secret",
    re.compile(r"\b(?=\w*\d)(?=\w*[A-Za-z])\w{32,}\b", re.ASCII),
)

# Order matters: specific rules run before broad ones so each value is
# redacted once, with the most accurate label.
DEFAULT_RULES = (
    EMAIL,
    SECRET_ASSIGNMENT,
    BEARER,
    PREFIXED_TOKEN,
    IPV6,
    IPV4,
    GENERIC_TOKEN,
)

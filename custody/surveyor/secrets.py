"""Pattern-based detection of credentials committed to a repository.

The patterns here are deliberately conservative: a false positive costs a
human thirty seconds, while a missed key can cost an account. Matched values
are never echoed in full — :func:`redact` keeps enough to locate the string
without reproducing the secret in the ledger or the console.
"""

from __future__ import annotations

import re
from pathlib import Path
from re import Pattern

from custody.findings import Finding, Pillar, Severity, anchor_ids, sort_findings

SECRET_PATTERNS: list[tuple[str, Pattern[str], Severity]] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), Severity.CRITICAL),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), Severity.CRITICAL),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), Severity.CRITICAL),
    ("private-key-block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("generic-assigned-secret", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*"
        r"['\"][A-Za-z0-9_\-/+]{16,}['\"]"
    ), Severity.HIGH),
]

PLACEHOLDER_HINTS = (
    "example",
    "placeholder",
    "changeme",
    "your-",
    "xxxx",
    "dummy",
    "fake",
    "<",
    "redacted",
)

MAX_SCAN_BYTES = 2_000_000
"""Files larger than this are not scanned.

The *caller* enforces this bound and records the file as skipped. An earlier
version returned an empty list from here, which rendered "not looked" exactly
like "looked and found nothing" - the precise confusion this project exists
to prevent.
"""


def redact(value: str) -> str:
    """Return a non-reversible preview of a matched secret."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * 8}{value[-2:]}"


def looks_like_placeholder(value: str) -> bool:
    """Return whether ``value`` is obviously a stand-in rather than a live key."""
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def survey_secrets(path: Path, rel: str) -> list[Finding]:
    """Scan one file for credential patterns.

    An unreadable file raises ``OSError`` to the caller, which records it as
    skipped. Swallowing the error here would report the file as clean without
    ever having looked at it.
    """
    text = path.read_text(encoding="utf-8", errors="replace")

    found: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern, severity in SECRET_PATTERNS:
            match = pattern.search(line)
            if match is None or looks_like_placeholder(match.group(0)):
                continue
            found.append(
                Finding(
                    id="",
                    rule=f"secret-{rule}",
                    pillar=Pillar.SECURITY,
                    severity=severity,
                    path=rel,
                    line=lineno,
                    message=f"Possible committed credential ({rule}).",
                    evidence=redact(match.group(0)),
                    detail={"pattern": rule},
                )
            )
    return sort_findings(anchor_ids(found))

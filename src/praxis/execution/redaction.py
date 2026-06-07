"""Redaction of secrets from audited parameters and error strings (SEC-9).

The audit log never stores output bodies (that is the audit module's job); this
module ensures the parameters and bounded error strings that *are* stored carry no
secret values. Redaction is applied to audited args before they are written and to
exception text before it becomes a bounded error.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

REDACTED = "[REDACTED]"

# Keys whose *value* is a secret regardless of its shape.
_SECRET_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|priv(ate)?[_-]?key|credential|"
    r"bearer|authorization|auth[_-]?token|access[_-]?key|session[_-]?key|"
    r"client[_-]?secret|otp|passphrase)",
    re.IGNORECASE,
)

# Value shapes that look like secrets even without a telling key. Each entry is a
# (pattern, replacement) pair; a replacement may keep a non-secret prefix (a flag
# name, or a URL user and host) while redacting the secret value itself.
_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
        REDACTED,
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),  # AWS access key id
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), REDACTED),  # AWS temporary access key id
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),  # GitHub tokens
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),  # Slack tokens
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b"),
        REDACTED,
    ),  # JWT
    # bearer/authorization inline in a string. Handles "Bearer <tok>",
    # "Authorization: <tok>", and the three-part "Authorization: Bearer <tok>"
    # so the token itself is redacted, not merely the scheme word.
    (re.compile(r"(?i)\b(?:bearer|authorization)\b[:=]?\s+(?:bearer\s+)?\S+"), REDACTED),
    # key=value or key: value where the key looks secret
    (
        re.compile(
            r"(?i)(pass(?:word|wd)?|secret|token|api[_-]?key|credential|passphrase)"
            r"\s*[=:]\s*\"?[^\s\"&]+\"?"
        ),
        REDACTED,
    ),
    # space- or equals-separated credential CLI flags: keep the flag, redact value
    (
        re.compile(
            r"(?i)(--?(?:password|passwd|token|api[_-]?key|secret|bearer|"
            r"auth[_-]?token|access[_-]?key|client[_-]?secret|passphrase))([=\s]+)\S+"
        ),
        r"\1\2" + REDACTED,
    ),
    # credentials embedded in a URL or DSN: scheme://user:SECRET@host. The password
    # runs up to the delimiting @ and may itself contain colons (a DSN password is
    # not colon-free), so the secret segment excludes only @, /, and whitespace.
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)[^\s@/]+@"), r"\1" + REDACTED + "@"),
)


def redact(text: str) -> str:
    """Redact secret-shaped substrings from a free-text string."""
    if not text:
        return text
    out = text
    for pat, replacement in _VALUE_PATTERNS:
        out = pat.sub(replacement, out)
    return out


def redact_args(args: Mapping[str, object]) -> dict[str, object]:
    """Redact a parameter mapping for audit.

    A value is redacted whole if its key looks secret; string values otherwise
    have secret-shaped substrings redacted. Nested mappings and sequences are
    handled recursively so a secret nested in a dict or list does not leak.
    """
    out: dict[str, object] = {}
    for key, value in args.items():
        if _SECRET_KEY.search(key):
            out[key] = REDACTED
        else:
            out[key] = _redact_value(value)
    return out


def _redact_value(value: object) -> object:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, Mapping):
        return redact_args(value)
    if isinstance(value, (list, tuple)):
        return [_redact_value(v) for v in value]
    return value

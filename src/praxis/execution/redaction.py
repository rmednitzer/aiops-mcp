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
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),  # GitHub classic tokens
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), REDACTED),  # GitHub fine-grained PAT
    # Provider tokens whose body runs UNBOUNDED from its length floor over the
    # token's full alphabet, so a longer-than-minimum token collapses whole rather
    # than leaving a tail in the audit log; a trailing `\b` after a `-`/`_` class is
    # not a reliable right anchor, so it is omitted here (BL-097).
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), REDACTED),  # GitLab PAT
    (re.compile(r"\bnpm_[A-Za-z0-9]{36,}"), REDACTED),  # npm token (>=36, collapse the tail)
    # PyPI upload token: the body is preceded by a fixed base64 macaroon prefix
    # (``AgEIcHlwaS5vcmc`` is base64 of "pypi.org"), a near-unique structural anchor.
    (re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{16,}"), REDACTED),  # PyPI upload token
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),  # Slack tokens
    (re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{16,}"), REDACTED),  # OpenAI scoped
    # Anthropic keys carry hyphens in the body (`sk-ant-api03-...`), so the generic `sk-`
    # value pattern below (alnum-only body) does not match them; redact them explicitly
    # before it (F-006). The body runs unbounded from its floor so a longer key collapses
    # whole rather than leaving a tail (BL-097 style).
    (re.compile(r"\bsk-ant-[a-z0-9]+-[A-Za-z0-9_\-]{20,}"), REDACTED),  # Anthropic API key
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), REDACTED),  # OpenAI / generic sk- key
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}"), REDACTED),  # HuggingFace token (F-006)
    (re.compile(r"\bdo[opr]_v1_[0-9a-f]{40,}"), REDACTED),  # DigitalOcean PAT/OAuth (F-006)
    (re.compile(r"\b[sr]k_(?:live|test|prod)_[A-Za-z0-9]{10,}"), REDACTED),  # Stripe
    (re.compile(r"\bAIza[A-Za-z0-9_\-]{35,}"), REDACTED),  # Google API key
    (re.compile(r"\bya29\.[A-Za-z0-9._\-]{20,}"), REDACTED),  # Google OAuth token
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b"),
        REDACTED,
    ),  # JWT
    # Authorization / Proxy-Authorization header: keep the header name, redact the
    # whole value to end-of-line or a closing quote. Stopping at EOL rather than at
    # the first space keeps a comma-separated AWS SigV4 credential
    # (Credential=..., SignedHeaders=..., Signature=<hex>) from leaking its signature.
    # The trailing `"?` consumes a closing quote so a quoted value leaves no dangling
    # quote behind.
    (
        re.compile(r"(?i)\b((?:proxy-)?authorization)\b\s*[:=]\s*\"?[^\"\r\n]+\"?"),
        r"\1: " + REDACTED,
    ),
    # A bare bearer token not behind an Authorization key.
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"), REDACTED),
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


# The MySQL family takes the password compactly attached to ``-p`` (``-psecret``),
# unlike the space/equals forms the credential-flag pattern above already covers.
# Redacting a bare ``-p<value>`` everywhere would over-scrub unrelated tools where
# ``-p`` means port (``ssh -p22``, ``nmap -p1-1000``), so the compact form is only
# redacted when a MySQL-family client also appears in the same string (BL-097).
_MYSQL_FAMILY = re.compile(r"\b(?:mysql\w*|mariadb\w*|mysqldump|mycli)\b", re.IGNORECASE)
# ``-p`` not preceded by a word char or dash (so ``--compress-p`` is not a hit), then
# a first password char that is not a space, ``=`` (the equals form is covered above),
# or ``-`` (so ``-p -h`` does not swallow the next flag), then the rest of the token.
_MYSQL_COMPACT_PW = re.compile(r"(?<![A-Za-z0-9-])(-p)[^\s=-]\S*")


def redact(text: str) -> str:
    """Redact secret-shaped substrings from a free-text string."""
    if not text:
        return text
    out = text
    for pat, replacement in _VALUE_PATTERNS:
        out = pat.sub(replacement, out)
    # Context-gated: only collapse a compact ``-p<password>`` when a MySQL-family
    # client is present, so ``-p`` meaning "port" for other tools is left intact.
    if _MYSQL_FAMILY.search(out):
        out = _MYSQL_COMPACT_PW.sub(r"\1" + REDACTED, out)
    return out


# Maximum nesting depth redaction will walk. A deeper subtree is replaced whole
# with a marker rather than recursed into, so a hostile, deeply nested args
# payload cannot drive redaction into a RecursionError inside the audited path
# (BL-077). 32 levels is far beyond any legitimate tool argument shape.
_MAX_DEPTH = 32
_TOO_DEEP = "[REDACTED:depth-limit]"


def redact_args(args: Mapping[str, object]) -> dict[str, object]:
    """Redact a parameter mapping for audit.

    A value is redacted whole if its key looks secret; string values otherwise
    have secret-shaped substrings redacted. Nested mappings and sequences are
    handled recursively, to a bounded depth (BL-077): a subtree nested deeper
    than the bound is replaced whole with a marker, never recursed into.
    """
    return _redact_mapping(args, depth=0)


def _redact_mapping(args: Mapping[str, object], *, depth: int) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in args.items():
        if _SECRET_KEY.search(str(key)):
            out[str(key)] = REDACTED
        else:
            out[str(key)] = _redact_value(value, depth=depth + 1)
    return out


def _redact_value(value: object, *, depth: int = 0) -> object:
    if isinstance(value, str):
        return redact(value)
    if depth >= _MAX_DEPTH:
        if isinstance(value, (Mapping, list, tuple)):
            return _TOO_DEEP
        return value
    if isinstance(value, Mapping):
        return _redact_mapping(value, depth=depth)
    if isinstance(value, (list, tuple)):
        return [_redact_value(v, depth=depth + 1) for v in value]
    return value

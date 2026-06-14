"""Request-scoped audit correlation identifiers (BL-101, ADR-0038).

Optional, additive ``request_id`` / ``client_id`` that the transport sets per request
and the single audited path (``run``) reads, so concurrent calls can be correlated to
their audit entries without timestamp matching. They are ambient via ``contextvars`` so
no tool signature changes, and absent (``None``) outside a request scope, e.g. the
session-header record or a direct library call.

The identifiers are transport- and client-supplied, so they are length-bounded before
they reach the audit record: a hostile or careless client cannot inflate the trail
(SEC-9 hygiene), and coercion never raises (invariant 3). ``client_id`` stays ``None``
for the single-client stdio transport; a multi-client transport (HTTP, BL-012) sets it.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator
from contextlib import contextmanager

# Cap on a client-supplied correlation id written to the audit log: ample for a UUID or
# a JSON-RPC id, bounded so a hostile client cannot bloat a record with a huge id.
MAX_ID_LEN = 128

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "praxis_request_id", default=None
)
_client_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "praxis_client_id", default=None
)


def bound_id(value: object) -> str | None:
    """Coerce a transport-supplied id to a bounded, non-empty string, or ``None``.

    Accepts the JSON-RPC id shapes (``str``, ``int``) and anything else via ``str``;
    returns ``None`` for ``None`` or an empty/whitespace id so an absent id stays
    absent. Truncates to ``MAX_ID_LEN`` and never raises, even on a hostile ``__str__``.
    """
    if value is None:
        return None
    try:
        text = value if isinstance(value, str) else str(value)
    except Exception:  # noqa: BLE001 - a hostile __str__ must not break correlation
        return None
    text = text.strip()
    if not text:
        return None
    return text[:MAX_ID_LEN]


@contextmanager
def request_scope(*, request_id: object = None, client_id: object = None) -> Iterator[None]:
    """Bind correlation ids for the duration of one request (set by the transport)."""
    rid = _request_id.set(bound_id(request_id))
    cid = _client_id.set(bound_id(client_id))
    try:
        yield
    finally:
        _request_id.reset(rid)
        _client_id.reset(cid)


def current_request_id() -> str | None:
    """The bounded request id for the current request scope, or ``None``."""
    return _request_id.get()


def current_client_id() -> str | None:
    """The bounded client id for the current request scope, or ``None``."""
    return _client_id.get()

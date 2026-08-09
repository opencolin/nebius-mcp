"""Helpers for awaiting Nebius long-running operations.

Every Nebius mutation returns an ``Operation`` (whether the SDK exposes it
typed or as a raw protobuf). The helpers here let tools either fire-and-forget
(returning the operation handle for the model to poll later) or block until
done within a bounded timeout.
"""

from __future__ import annotations

from typing import Any

from .sanitize import redact

DEFAULT_WAIT_TIMEOUT_SECONDS = 300
DEFAULT_POLL_INTERVAL_SECONDS = 2.0


async def maybe_wait(operation: Any, *, wait: bool, timeout_seconds: int) -> dict[str, Any]:
    """Optionally await an operation; return a dict summary either way.

    The ``Operation`` proto carries id / resource_id / done / successful /
    status / description. Status is a grpc StatusCode-like enum; we stringify
    it so JSON serialization is stable.
    """
    if wait:
        await operation.wait(
            interval=DEFAULT_POLL_INTERVAL_SECONDS,
            timeout=float(timeout_seconds),
        )
    return _summarize(operation)


def _summarize(op: Any) -> dict[str, Any]:
    """Build the model-facing summary of an operation, redacted.

    The redaction is here rather than at the nine call sites, and rather than in
    ``sanitize.wrap``, for two different reasons.

    Here, because this function is the only place an ``Operation`` becomes a
    plain dict: every tool that mutates anything reaches the model through
    ``maybe_wait`` and therefore through this line. A caller that forgets is not
    a failure mode this can have.

    Not in ``wrap``, because ``wrap`` is also where every list tool assembles
    ``next_page_token`` — a field name that matches the denylist's ``token``
    substring rule. Redacting centrally there would replace every pagination
    cursor with ``<redacted>``, which fails silently and looks like the end of
    the results. See ``redact``'s docstring.

    ``description`` is the field that motivates this: it is free text the
    control plane chooses, so it can quote a resource name, and resource names
    are attacker-writable by anyone with write access to the account. Neither
    half of the sanitizer reached it before — key-name matching never saw a key,
    and the value patterns were never applied to the string.

    Redacting the whole summary rather than just ``description`` is deliberate
    and was checked for false positives: none of the six keys matches
    ``_is_sensitive_key``, and Nebius resource and operation IDs do not match any
    value pattern, so the identifiers a caller needs in order to poll survive
    intact. ``tests/unit/test_operation.py`` pins both halves of that.
    """
    summary: dict[str, Any] = {
        "operation_id": getattr(op, "id", None),
        "resource_id": getattr(op, "resource_id", None),
        "done": bool(getattr(op, "done", False)),
        "successful": bool(getattr(op, "successful", False)),
        "status": str(getattr(op, "status", "UNKNOWN")),
        "description": getattr(op, "description", None),
    }
    redacted: dict[str, Any] = redact(summary)
    return redacted

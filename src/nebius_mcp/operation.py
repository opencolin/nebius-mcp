"""Helpers for awaiting Nebius long-running operations.

Every Nebius mutation returns an ``Operation`` (whether the SDK exposes it
typed or as a raw protobuf). The helpers here let tools either fire-and-forget
(returning the operation handle for the model to poll later) or block until
done within a bounded timeout.
"""

from __future__ import annotations

from typing import Any

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
    return {
        "operation_id": getattr(op, "id", None),
        "resource_id": getattr(op, "resource_id", None),
        "done": bool(getattr(op, "done", False)),
        "successful": bool(getattr(op, "successful", False)),
        "status": str(getattr(op, "status", "UNKNOWN")),
        "description": getattr(op, "description", None),
    }

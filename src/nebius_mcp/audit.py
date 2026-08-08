"""Structured audit logging for tool invocations.

We log: timestamp, tool, an SHA-256 hash of args (not raw — args may contain
identifiers we do not want to ship to log aggregation), the active mode, and
the outcome (ok/error). We never log tokens, secret values, or full payloads.

The ``error`` field is free-form text from an SDK exception, so it goes through
the sanitizer before emission — an operator's log aggregator is a wider
audience than the operator.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from typing import Any

import structlog

from .sanitize import DATA_PREAMBLE, redact_text

_initialized = False

# Cap on the ``error`` field of an audit record. Log aggregators bill by volume
# and truncate lines unpredictably; the message here only has to identify which
# failure happened, not reproduce it. Smaller than the model-facing cap in
# errors.py because nothing downstream reads this to recover.
MAX_AUDIT_ERROR_CHARS = 200


def _init() -> None:
    global _initialized
    if _initialized:
        return
    level = os.environ.get("NEBIUS_MCP_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stderr,
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
        # MUST be stderr. structlog does not route through stdlib logging here,
        # so basicConfig(stream=...) above does not apply to it — its default
        # PrintLoggerFactory writes to stdout, which on the stdio transport IS
        # the JSON-RPC channel. Every audit line then lands in the protocol
        # stream and clients report parse errors on each tool call.
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
    _initialized = True


def _hash_args(args: Any) -> str:
    blob = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]  # short prefix is enough to correlate


def _audit_error_text(error: str) -> str:
    """Prepare an exception string for the log sink.

    A tool failure arrives here as the ``ToolError`` built by
    ``errors.to_tool_error``, which prefixes the sanitizer's data preamble for
    the model's benefit. A log aggregator is not a model, and the preamble is
    longer than MAX_AUDIT_ERROR_CHARS — left in place it would be the entire
    record and the actual failure would be truncated away.
    """
    detail = error
    if detail.startswith(DATA_PREAMBLE):
        detail = detail[len(DATA_PREAMBLE) :].lstrip()
    return redact_text(detail, max_chars=MAX_AUDIT_ERROR_CHARS)


def log_call(*, tool: str, args: Any, mode: str, outcome: str, error: str | None = None) -> None:
    _init()
    log = structlog.get_logger("nebius_mcp.audit")
    payload: dict[str, Any] = {
        "tool": tool,
        "args_hash": _hash_args(args),
        "mode": mode,
        "outcome": outcome,
    }
    if error:
        payload["error"] = _audit_error_text(error)
    log.info("tool_call", **payload)


def make_middleware() -> Any:
    """FastMCP middleware that audit-logs every tool invocation."""
    from fastmcp.server.middleware import Middleware

    class AuditMiddleware(Middleware):
        async def on_call_tool(self, context: Any, call_next: Any) -> Any:
            from .server import is_write_mode

            tool = context.message.name
            args = context.message.arguments or {}
            mode = "write" if is_write_mode() else "read"
            try:
                result = await call_next(context)
            except Exception as exc:
                # Pass the full text: log_call redacts before it truncates, and
                # slicing here first can cut a token in half so no pattern
                # matches it any more.
                log_call(tool=tool, args=args, mode=mode, outcome="error", error=str(exc))
                raise
            log_call(tool=tool, args=args, mode=mode, outcome="ok")
            return result

    return AuditMiddleware()

"""Structured audit logging for tool invocations.

We log: timestamp, tool, an SHA-256 hash of args (not raw — args may contain
identifiers we do not want to ship to log aggregation), the active mode, and
the outcome. We never log tokens, secret values, or full payloads.

The outcome is one of:

``ok``
    The tool ran and returned.
``previewed``
    The tool returned the dry-run envelope of the confirm two-step and did
    nothing else. Both halves of that two-step return without raising, so
    without this distinction a previewed delete and an executed one are the
    same record (R-011).
``error``
    The tool raised.

The ``previewed`` signal comes from :func:`confirm.preview_or_execute`, the
only code that knows which of its two paths it took — deliberately not from
inspecting the value the tool returned. Recognising a dry run by the shape of
its payload would make the audit record a guess about someone else's data
structure, and it would start lying the moment that structure changed.

The ``error`` field is free-form text from an SDK exception, so it goes through
the sanitizer before emission — an operator's log aggregator is a wider
audience than the operator.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import logging
import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import structlog

from .sanitize import DATA_PREAMBLE, redact_text

_initialized = False

# Cap on the ``error`` field of an audit record. Log aggregators bill by volume
# and truncate lines unpredictably; the message here only has to identify which
# failure happened, not reproduce it. Smaller than the model-facing cap in
# errors.py because nothing downstream reads this to recover.
MAX_AUDIT_ERROR_CHARS = 200


@dataclass
class CallFlags:
    """What one tool call reported about itself while it was running.

    ``previewed`` is set by :func:`confirm.preview_or_execute` when it returned
    a dry-run envelope instead of clearing the caller to execute. Nothing else
    writes to it, and nothing reads it but the middleware that opened the
    scope.
    """

    previewed: bool = False


_call_flags: contextvars.ContextVar[CallFlags | None] = contextvars.ContextVar(
    "nebius_mcp_call_flags", default=None
)


@contextlib.contextmanager
def call_scope() -> Iterator[CallFlags]:
    """Install a fresh :class:`CallFlags` for the duration of one tool call.

    The information flows *outwards*: the middleware opens the scope, the tool
    runs inside it, and code deep in the call mutates the object the middleware
    is still holding.

    That direction is the point. Setting a ContextVar *inside* the tool and
    reading it outside is the obvious shape and it is fragile — if any layer in
    between runs the tool in a fresh ``asyncio.Task`` or on a worker thread,
    the inner ``set`` lands on a copy of the context and the outer read never
    sees it, so a preview would quietly be recorded as ``ok``. A copied context
    still shares the *object* a var points at, so mutating a cell the outer
    frame installed survives any such hop, and two calls in flight at once each
    mutate their own cell.

    It also makes the reset structural rather than remembered: every call gets
    its own object and the var is restored on the way out, including when the
    tool raises, so a tool that previews cannot leave the flag set for the next
    unrelated call.

    A tool that never previews pays one ``ContextVar.set`` and one ``reset``
    and is otherwise untouched.
    """
    flags = CallFlags()
    token = _call_flags.set(flags)
    try:
        yield flags
    finally:
        _call_flags.reset(token)


def mark_previewed() -> None:
    """Report that the current tool call previewed instead of executing.

    Outside a :func:`call_scope` — a direct call in a test, or a tool invoked
    without the middleware — there is nothing to write to and this is a no-op.
    It is a report, not a control: nothing about the confirm flow depends on
    whether anyone was listening.
    """
    flags = _call_flags.get()
    if flags is not None:
        flags.previewed = True


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
            # Hashed whole, `confirm_token` included. That is the only reason a
            # preview and the confirming call have ever differed at all, and
            # the only thing tying a record to a specific token: do not filter.
            args = context.message.arguments or {}
            mode = "write" if is_write_mode() else "read"
            # Opened for every tool, not just the destructive ones: the
            # middleware cannot know which is which, and a tool that never
            # previews just leaves the flag alone.
            with call_scope() as flags:
                try:
                    result = await call_next(context)
                except Exception as exc:
                    # Pass the full text: log_call redacts before it truncates,
                    # and slicing here first can cut a token in half so no
                    # pattern matches it any more.
                    log_call(tool=tool, args=args, mode=mode, outcome="error", error=str(exc))
                    raise
                outcome = "previewed" if flags.previewed else "ok"
            log_call(tool=tool, args=args, mode=mode, outcome=outcome)
            return result

    return AuditMiddleware()

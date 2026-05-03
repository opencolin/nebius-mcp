"""Structured audit logging for tool invocations.

We log: timestamp, tool, an SHA-256 hash of args (not raw — args may contain
identifiers we do not want to ship to log aggregation), the active mode, and
the outcome (ok/error). We never log tokens, secret values, or full payloads.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

import structlog

_initialized = False


def _init() -> None:
    global _initialized
    if _initialized:
        return
    level = os.environ.get("NEBIUS_MCP_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=__import__("sys").stderr,
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
        cache_logger_on_first_use=True,
    )
    _initialized = True


def _hash_args(args: Any) -> str:
    blob = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]  # short prefix is enough to correlate


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
        payload["error"] = error
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
                log_call(tool=tool, args=args, mode=mode, outcome="error", error=str(exc)[:200])
                raise
            log_call(tool=tool, args=args, mode=mode, outcome="ok")
            return result

    return AuditMiddleware()

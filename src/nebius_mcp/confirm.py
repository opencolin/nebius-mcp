"""Dry-run / confirm-token machinery for irreversible operations.

The pattern:

  1. Model calls a destructive tool with ``confirm_token=None`` (or unset).
  2. We refuse to execute, return a *preview* of what would happen plus a
     short-lived single-use token bound to (tool_name, args).
  3. Model calls the same tool again with the matching ``confirm_token``.
  4. We consume the token (single use, expires) and execute the real call.

This mirrors AWS Labs / Cloudflare patterns and is the spec-recommended
mitigation for tools annotated ``destructiveHint=True`` against indirect
prompt injection that flips a model into deleting things.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass

from fastmcp.exceptions import ToolError

from .server import is_write_mode

DEFAULT_TTL_SECONDS = 120
_TICKET_LOCK = threading.Lock()


@dataclass(frozen=True)
class ConfirmTicket:
    token: str
    tool: str
    args_hash: str
    issued_at: float
    expires_at: float


_active: dict[str, ConfirmTicket] = {}


def _hash_args(args: object) -> str:
    blob = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def issue(tool: str, args: object, ttl: int = DEFAULT_TTL_SECONDS) -> ConfirmTicket:
    now = time.time()
    ticket = ConfirmTicket(
        token=secrets.token_urlsafe(16),
        tool=tool,
        args_hash=_hash_args(args),
        issued_at=now,
        expires_at=now + ttl,
    )
    with _TICKET_LOCK:
        _gc(now)
        _active[ticket.token] = ticket
    return ticket


def _gc(now: float) -> None:
    expired = [t for t, ticket in _active.items() if ticket.expires_at < now]
    for t in expired:
        _active.pop(t, None)


def consume(tool: str, args: object, token: str) -> bool:
    now = time.time()
    args_hash = _hash_args(args)
    with _TICKET_LOCK:
        _gc(now)
        ticket = _active.pop(token, None)
    if ticket is None:
        return False
    if ticket.tool != tool:
        return False
    if ticket.args_hash != args_hash:
        return False
    return ticket.expires_at >= now


def reset() -> None:
    """Drop all in-flight tickets. Intended for tests."""
    with _TICKET_LOCK:
        _active.clear()


def require_write(tool: str) -> None:
    """Raise a ToolError if the server is not in write mode."""
    if not is_write_mode():
        raise ToolError(
            f"{tool}: write mode is disabled. Set NEBIUS_MCP_MODE=write to enable destructive "
            "operations. The server defaults to read-only as a safety measure."
        )


def preview_or_execute(
    *,
    tool: str,
    args: object,
    confirm_token: str | None,
    preview: object,
    ttl: int = DEFAULT_TTL_SECONDS,
) -> object | None:
    """Implement the dry_run/confirm gate for destructive tools.

    Returns:
        The preview envelope (dict) if no valid confirm_token was supplied
        — caller should ``return`` it directly to the LLM.

        ``None`` if the token is valid and the caller should proceed with
        the real execution.
    """
    require_write(tool)
    if confirm_token and consume(tool, args, confirm_token):
        return None  # caller proceeds

    ticket = issue(tool, args, ttl=ttl)
    return {
        "_preamble": (
            "DRY RUN. This destructive operation has NOT executed. To confirm, "
            "call the same tool again with confirm_token set to the value below. "
            f"The token is single-use and expires in {ttl} seconds."
        ),
        "preview": preview,
        "confirm_token": ticket.token,
        "expires_at": ticket.expires_at,
        "tool": tool,
    }

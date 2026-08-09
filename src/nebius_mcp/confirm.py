"""Dry-run / confirm-token machinery for irreversible operations.

The pattern:

  1. Model calls a destructive tool with ``confirm_token=None`` (or unset).
  2. We refuse to execute, return a *preview* of what would happen plus a
     short-lived single-use token bound to (tool_name, args).
  3. Model calls the same tool again with the matching ``confirm_token``.
  4. We consume the token (single use, expires) and execute the real call.

What this is, and what it is not
--------------------------------
It is a mistake guard. One mis-aimed call cannot delete anything, and the
exact target appears in the transcript before the deletion happens, where a
person reading along can stop it.

It is not a defense against prompt injection. The token is handed to the
model and the model replays it; no step requires a human. Both calls can be
issued back to back by the same caller with nobody else involved —
``tests/unit/test_destructive_flow.py::test_delete_with_confirm_token_executes``
does precisely that. Whatever can make a model call a delete once can make it
call the delete twice.

What bounds the damage is the write-mode gate (:func:`require_write`) and the
permissions on the credentials the server runs with. See ``SECURITY.md``.
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
    """Spend a ticket, returning whether it authorised this exact call.

    The ticket is popped *before* ``tool`` and ``args_hash`` are compared, so a
    mismatched replay burns the token and forces a fresh dry run rather than
    letting the caller retry against the same one. That is deliberate for a
    mistake guard: a token that survives being presented with the wrong
    arguments is a token that can be brute-forced against, and re-previewing
    costs one call. Do not "fix" this into validate-then-pop.
    """
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

    Both paths return normally, so from the outside the two halves of the
    two-step are indistinguishable — which is how the audit log came to record
    a previewed delete and a real one identically (R-011). This function is the
    only code that knows which path it took, so the preview branch says so, via
    :func:`audit.mark_previewed`.
    """
    require_write(tool)
    if confirm_token and consume(tool, args, confirm_token):
        return None  # caller proceeds

    # The flag lives in audit because audit owns the record vocabulary and is
    # the only reader. Imported here rather than at module scope so that this
    # module — which every destructive tool imports, and which the write gate
    # sits in — does not pull structlog in behind it just to report an outcome.
    from .audit import mark_previewed

    ticket = issue(tool, args, ttl=ttl)
    mark_previewed()
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

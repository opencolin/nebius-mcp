"""Error mapping for tools.

Nebius SDK raises ``RequestError`` (or subclasses of ``SDKError``) for any
API call failure. We wrap these into ``ToolError`` with a structured
message so the LLM gets a recoverable signal instead of a transport-level
exception.

FastMCP introspects tool signatures, so we cannot use a *args/**kwargs
wrapper here. The ``safe`` helper is meant to be called inside each tool
body around the SDK call.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import TypeVar

from fastmcp.exceptions import ToolError

from .auth import AuthError

T = TypeVar("T")


def to_tool_error(exc: Exception) -> ToolError:
    """Convert a low-level exception to a ToolError with structured detail."""
    if isinstance(exc, AuthError):
        return ToolError(f"AuthError: {exc}")
    name = exc.__class__.__name__
    return ToolError(f"NebiusAPIError ({name}): {exc!s}")


async def safe(coro: Awaitable[T]) -> T:
    """Await ``coro`` and convert any exception into a ToolError.

    Usage inside a tool:

        resp = await safe(client.list(req))
    """
    try:
        return await coro
    except ToolError:
        raise
    except Exception as exc:
        raise to_tool_error(exc) from exc

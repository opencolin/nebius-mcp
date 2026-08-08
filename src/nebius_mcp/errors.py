"""Error mapping for tools.

Nebius SDK raises ``RequestError`` (or subclasses of ``SDKError``) for any
API call failure. We wrap these into ``ToolError`` with a structured
message so the LLM gets a recoverable signal instead of a transport-level
exception.

The wrapped message goes through the same sanitizer as a successful response:
an SDK exception string can quote request metadata, and a failure inside a
secrets tool can quote the payload it was reading.

FastMCP introspects tool signatures, so we cannot use a *args/**kwargs
wrapper here. The ``safe`` helper is meant to be called inside each tool
body around the SDK call.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import TypeVar

from fastmcp.exceptions import ToolError

from .auth import AuthError
from .sanitize import DATA_PREAMBLE, redact_text

T = TypeVar("T")

# Cap on the exception detail carried into a ToolError, excluding the preamble.
# gRPC status details can echo the whole failed request — metadata headers
# included — and an unbounded error crowds the conversation out of the model's
# context window. Long enough to keep a status code, a message and a resource
# id; short enough that a pathological error costs a few hundred tokens.
MAX_ERROR_DETAIL_CHARS = 512


def to_tool_error(exc: Exception) -> ToolError:
    """Convert a low-level exception to a ToolError with structured detail.

    The detail is redacted and capped at :data:`MAX_ERROR_DETAIL_CHARS`, and is
    framed with the sanitizer's data preamble. API error strings are
    attacker-influenceable — a resource named with an injection payload is
    quoted verbatim in a not-found message — so the model has to read them as
    data, exactly like a successful response body.
    """
    if isinstance(exc, AuthError):
        detail = f"AuthError: {exc}"
    else:
        detail = f"NebiusAPIError ({exc.__class__.__name__}): {exc!s}"
    safe_detail = redact_text(detail, max_chars=MAX_ERROR_DETAIL_CHARS)
    return ToolError(f"{DATA_PREAMBLE}\n\n{safe_detail}")


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

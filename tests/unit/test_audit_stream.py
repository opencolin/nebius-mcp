"""What the audit log emits, and where.

The server speaks MCP over stdio, so stdout is the JSON-RPC channel. A log line
written there is parsed by the client as a protocol message and surfaces as a
JSONRPCError on every single tool call.

This is invisible to in-process tests (`Client(app)` never opens a pipe), so the
check is on the stream itself: run a real subprocess and assert stdout is empty
while the audit record lands on stderr. The subprocess is also the only way to
read a record's contents, because structlog binds its output stream once, on
first use, and never sees a `sys.stderr` that pytest swapped in afterwards.

The second half of the file is about *which* record the middleware asks for —
in particular that a previewed destructive call and an executed one are no
longer the same record (R-011). Those tests run in-process against a real
FastMCP app and capture the arguments to `log_call` rather than its output,
because the question is what the middleware decided, not how structlog renders
it.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from nebius_mcp.audit import MAX_AUDIT_ERROR_CHARS, _hash_args, make_middleware
from nebius_mcp.confirm import preview_or_execute
from nebius_mcp.confirm import reset as reset_tickets

_EMIT = """
from nebius_mcp.audit import log_call
log_call(tool="t", args={"a": 1}, mode="read", outcome="ok")
"""

_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYS0xIn0.c2lnbmF0dXJl"

_EMIT_ERROR = f"""
from nebius_mcp.audit import log_call
log_call(
    tool="t",
    args={{}},
    mode="read",
    outcome="error",
    error="failed with authorization=Bearer {_JWT} secret_key=abc " + "pad " * 200,
)
"""

_EMIT_TOOL_ERROR = """
from nebius_mcp.audit import log_call
from nebius_mcp.errors import to_tool_error

log_call(
    tool="t",
    args={},
    mode="read",
    outcome="error",
    error=str(to_tool_error(RuntimeError("quota exceeded"))),
)
"""


def test_audit_writes_to_stderr_not_stdout() -> None:
    proc = subprocess.run(
        [sys.executable, "-c", _EMIT],
        capture_output=True,
        text=True,
        check=True,
    )

    assert proc.stdout == "", (
        f"audit log leaked to stdout, which is the MCP JSON-RPC channel; got: {proc.stdout!r}"
    )

    record = json.loads(proc.stderr.strip().splitlines()[-1])
    assert record["event"] == "tool_call"
    assert record["tool"] == "t"
    assert record["outcome"] == "ok"
    # Raw args must never be logged — only their hash.
    assert "args" not in record
    assert record["args_hash"]


def test_audit_error_field_is_redacted_and_capped() -> None:
    """An SDK exception string is untrusted text on its way to a log sink.

    Redaction has to happen before truncation: a token cut at the cap no longer
    matches its pattern, and the head of a secret is still a secret.
    """
    proc = subprocess.run(
        [sys.executable, "-c", _EMIT_ERROR],
        capture_output=True,
        text=True,
        check=True,
    )

    assert proc.stdout == ""

    record = json.loads(proc.stderr.strip().splitlines()[-1])
    error = record["error"]

    assert "<redacted>" in error
    assert _JWT not in error
    assert "secret_key=abc" not in error
    assert len(error) <= MAX_AUDIT_ERROR_CHARS
    assert error.endswith("...[truncated]")


def test_audit_record_keeps_the_failure_not_the_preamble() -> None:
    """The middleware logs the ToolError, which is framed for the model.

    That framing is longer than the audit cap, so without stripping it the
    record would be all preamble and no failure.
    """
    proc = subprocess.run(
        [sys.executable, "-c", _EMIT_TOOL_ERROR],
        capture_output=True,
        text=True,
        check=True,
    )

    error = json.loads(proc.stderr.strip().splitlines()[-1])["error"]

    assert error.startswith("NebiusAPIError (RuntimeError): quota exceeded")
    assert "untrusted" not in error


# --- which outcome the middleware records (R-011) ----------------------------


@pytest.fixture
def records(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture the keyword arguments of every `log_call` the middleware makes."""
    seen: list[dict[str, Any]] = []

    def fake_log_call(**kwargs: Any) -> None:
        seen.append(kwargs)

    monkeypatch.setattr("nebius_mcp.audit.log_call", fake_log_call)
    return seen


@pytest.fixture(autouse=True)
def _write_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_tickets()
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")


def _harness_app() -> FastMCP:
    """A miniature server: one tool that previews, one that never does, one that fails.

    Deliberately not the real app. The middleware is generic over all 57 tools
    and the claim under test is about that generic path, so the tools here are
    the smallest things that exercise each branch of it. The real tools get
    their own test below.
    """
    app: FastMCP = FastMCP(name="audit-harness")
    app.add_middleware(make_middleware())

    @app.tool(name="harness_delete")
    async def harness_delete(id: str, confirm_token: str | None = None) -> dict[str, Any]:
        gate = preview_or_execute(
            tool="harness_delete",
            args={"id": id},
            confirm_token=confirm_token,
            preview={"action": f"delete {id}"},
        )
        if gate is not None:
            return gate  # type: ignore[return-value]
        return {"deleted": id}

    @app.tool(name="harness_slow_delete")
    async def harness_slow_delete(id: str) -> dict[str, Any]:
        gate = preview_or_execute(
            tool="harness_slow_delete",
            args={"id": id},
            confirm_token=None,
            preview={"action": f"delete {id}"},
        )
        # Hold the call open across the point where another tool call starts,
        # finishes, and tears down its own scope.
        await asyncio.sleep(0.05)
        return gate  # type: ignore[return-value]

    @app.tool(name="harness_list")
    async def harness_list() -> dict[str, Any]:
        return {"items": []}

    @app.tool(name="harness_boom")
    async def harness_boom() -> dict[str, Any]:
        raise ToolError("harness_boom: exploded")

    return app


@pytest.mark.asyncio
async def test_preview_logs_previewed_and_the_confirming_call_logs_ok(
    records: list[dict[str, Any]],
) -> None:
    """The whole point of R-011: the two halves of the two-step are not one outcome."""
    app = _harness_app()
    async with Client(app) as c:
        first = await c.call_tool("harness_delete", {"id": "i-1"})
        second = await c.call_tool(
            "harness_delete", {"id": "i-1", "confirm_token": first.data["confirm_token"]}
        )

    assert second.data == {"deleted": "i-1"}  # the second call really did execute
    assert [r["outcome"] for r in records] == ["previewed", "ok"]


@pytest.mark.asyncio
async def test_the_two_records_still_differ_by_args_hash(
    records: list[dict[str, Any]],
) -> None:
    """R-011 noted the pair was already distinguishable, faintly. Keep it that way.

    `confirm_token` is one of the tool's own arguments, so it is inside the
    blob `audit._hash_args` digests and the executing call hashes differently
    from the preview. Hashing a filtered copy of the arguments would take that
    away, and it is the only thing tying a record to a specific token.
    """
    app = _harness_app()
    async with Client(app) as c:
        first = await c.call_tool("harness_delete", {"id": "i-1"})
        token = first.data["confirm_token"]
        await c.call_tool("harness_delete", {"id": "i-1", "confirm_token": token})

    preview_args, execute_args = (r["args"] for r in records)
    assert "confirm_token" not in preview_args
    assert execute_args["confirm_token"] == token
    assert _hash_args(preview_args) != _hash_args(execute_args)


@pytest.mark.asyncio
async def test_a_tool_that_never_previews_logs_ok(records: list[dict[str, Any]]) -> None:
    app = _harness_app()
    async with Client(app) as c:
        await c.call_tool("harness_list", {})

    assert [r["outcome"] for r in records] == ["ok"]


@pytest.mark.asyncio
async def test_a_failing_tool_still_logs_error(records: list[dict[str, Any]]) -> None:
    app = _harness_app()
    async with Client(app) as c:
        with pytest.raises(Exception, match="exploded"):
            await c.call_tool("harness_boom", {})

    assert [r["outcome"] for r in records] == ["error"]
    assert "exploded" in records[0]["error"]


@pytest.mark.asyncio
async def test_previewed_does_not_leak_into_the_next_call(
    records: list[dict[str, Any]],
) -> None:
    """A preview must not colour the next, unrelated tool call."""
    app = _harness_app()
    async with Client(app) as c:
        await c.call_tool("harness_delete", {"id": "i-1"})
        await c.call_tool("harness_list", {})

    assert [(r["tool"], r["outcome"]) for r in records] == [
        ("harness_delete", "previewed"),
        ("harness_list", "ok"),
    ]


@pytest.mark.asyncio
async def test_concurrent_calls_do_not_borrow_each_others_flag(
    records: list[dict[str, Any]],
) -> None:
    """One call is mid-preview while another starts and finishes.

    Two failure modes this would catch: the plain call marking itself
    `previewed` because a flag was ambient, and the previewing call losing its
    own flag because the other call's scope tore down over the top of it.
    """
    app = _harness_app()
    async with Client(app) as c:
        slow = asyncio.create_task(c.call_tool("harness_slow_delete", {"id": "i-1"}))
        await asyncio.sleep(0.01)
        await c.call_tool("harness_list", {})
        await slow

    assert dict((r["tool"], r["outcome"]) for r in records) == {
        "harness_slow_delete": "previewed",
        "harness_list": "ok",
    }
    assert len(records) == 2


@pytest.mark.asyncio
async def test_a_real_delete_previews_then_executes(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, Any]]
) -> None:
    """Same claim, through the real server and a real destructive tool."""
    from nebius.api.nebius.compute.v1 import InstanceServiceClient

    from nebius_mcp.client import reset_clients
    from nebius_mcp.server import _build_app

    reset_clients()
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)

    op = MagicMock()
    op.id = "operation-xxx"
    op.resource_id = "computeinstance-deleted"
    op.done = True
    op.successful = True
    op.status = "OK"
    op.description = "delete instance"

    async def _wait(**_: Any) -> None:
        return None

    op.wait = _wait

    async def _returns_op() -> Any:
        return op

    client_mock = MagicMock()
    client_mock.delete = MagicMock(return_value=_returns_op())
    monkeypatch.setattr(
        "nebius_mcp.tools.compute.service",
        lambda cls: client_mock if cls is InstanceServiceClient else MagicMock(),
    )
    monkeypatch.setattr("nebius_mcp.tools._ops_helpers.service", lambda cls: client_mock)

    app = _build_app()
    async with Client(app) as c:
        first = await c.call_tool("compute_delete_instance", {"id": "computeinstance-1"})
        await c.call_tool(
            "compute_delete_instance",
            {"id": "computeinstance-1", "confirm_token": first.data["confirm_token"]},
        )

    assert client_mock.delete.call_count == 1  # exactly one of the two calls destroyed anything
    assert [r["outcome"] for r in records] == ["previewed", "ok"]


@pytest.mark.asyncio
async def test_a_secret_reveal_preview_is_logged_previewed(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, Any]]
) -> None:
    """A preview of a secret reveal is as interesting to an auditor as a preview of a delete.

    No SDK mock is needed: the preview branch returns before the tool ever
    reaches for a client, which is the property being relied on.
    """
    from nebius_mcp.client import reset_clients
    from nebius_mcp.server import _build_app
    from nebius_mcp.tools.secrets import ALLOW_REVEAL_ENV

    reset_clients()
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    monkeypatch.setenv(ALLOW_REVEAL_ENV, "1")

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("secrets_reveal_payload", {"secret_id": "mysterybox-1"})

    assert "confirm_token" in result.data
    assert [(r["tool"], r["outcome"]) for r in records] == [("secrets_reveal_payload", "previewed")]

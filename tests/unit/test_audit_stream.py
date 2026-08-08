"""What the audit log emits, and where.

The server speaks MCP over stdio, so stdout is the JSON-RPC channel. A log line
written there is parsed by the client as a protocol message and surfaces as a
JSONRPCError on every single tool call.

This is invisible to in-process tests (`Client(app)` never opens a pipe), so the
check is on the stream itself: run a real subprocess and assert stdout is empty
while the audit record lands on stderr. The subprocess is also the only way to
read a record's contents, because structlog binds its output stream once, on
first use, and never sees a `sys.stderr` that pytest swapped in afterwards.
"""

from __future__ import annotations

import json
import subprocess
import sys

from nebius_mcp.audit import MAX_AUDIT_ERROR_CHARS

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

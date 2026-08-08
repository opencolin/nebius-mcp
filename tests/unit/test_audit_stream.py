"""The audit log must never touch stdout.

The server speaks MCP over stdio, so stdout is the JSON-RPC channel. A log line
written there is parsed by the client as a protocol message and surfaces as a
JSONRPCError on every single tool call.

This is invisible to in-process tests (`Client(app)` never opens a pipe), so the
check is on the stream itself: run a real subprocess and assert stdout is empty
while the audit record lands on stderr.
"""

from __future__ import annotations

import json
import subprocess
import sys

_EMIT = """
from nebius_mcp.audit import log_call
log_call(tool="t", args={"a": 1}, mode="read", outcome="ok")
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

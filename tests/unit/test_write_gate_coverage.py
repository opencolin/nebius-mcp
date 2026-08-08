"""Every mutating tool must refuse to run in read-only mode.

This is the load-bearing safety property: someone can point an agent at their
cloud account and trust that nothing changes until they opt in. A single tool
that forgets `require_write` silently breaks that promise, and the failure is
invisible until something is already deleted.

Rather than spot-checking known tools, this enumerates the live tool surface
and asserts the invariant over everything annotated as mutating — so a tool
added later is covered without anyone remembering to add a test.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastmcp import Client

from nebius_mcp.server import _build_app


def _plausible_args(schema: dict[str, Any] | None) -> dict[str, Any]:
    """Build minimally valid arguments so the call reaches the write gate.

    Schema validation runs before the tool body, so required fields must be
    present or the call fails for the wrong reason and the test passes vacuously.
    """
    schema = schema or {}
    properties = schema.get("properties") or {}
    args: dict[str, Any] = {}

    for name in schema.get("required") or []:
        spec = properties.get(name, {})
        if "enum" in spec:
            args[name] = spec["enum"][0]
        elif spec.get("type") == "integer":
            args[name] = 1
        elif spec.get("type") == "boolean":
            args[name] = False
        else:
            args[name] = "computeinstance-abc123456789"
    return args


@pytest.fixture(autouse=True)
def _read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEBIUS_MCP_MODE", raising=False)
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")


async def test_every_mutating_tool_is_write_gated() -> None:
    app = _build_app()
    tools = [t.to_mcp_tool() for t in await app.list_tools()]

    mutating = [
        t for t in tools if t.annotations is not None and t.annotations.readOnlyHint is False
    ]
    assert mutating, "no mutating tools found — the annotation contract changed"

    ungated: list[str] = []
    async with Client(app) as client:
        for tool in mutating:
            result = await client.call_tool(
                tool.name, _plausible_args(tool.inputSchema), raise_on_error=False
            )
            body = result.content[0].text if result.content else ""
            if not (result.is_error and "write mode is disabled" in body):
                ungated.append(f"{tool.name}: {body[:120]}")

    assert not ungated, "mutating tools that did NOT refuse in read mode:\n" + "\n".join(ungated)


async def test_read_tools_are_not_write_gated() -> None:
    """The gate must not have crept onto read tools, which would break read-only use."""
    app = _build_app()
    tools = [t.to_mcp_tool() for t in await app.list_tools()]

    read_only = [
        t
        for t in tools
        # No required args keeps this to tools we can call without inventing IDs.
        if t.annotations is not None
        and t.annotations.readOnlyHint is True
        and not (t.inputSchema or {}).get("required")
    ]
    assert read_only, "no argument-free read tools found"

    async with Client(app) as client:
        for tool in read_only:
            result = await client.call_tool(tool.name, {}, raise_on_error=False)
            body = result.content[0].text if result.content else ""
            assert "write mode is disabled" not in body, (
                f"{tool.name} is annotated read-only but is write-gated"
            )

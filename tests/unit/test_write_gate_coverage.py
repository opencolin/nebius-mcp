"""Whole-tool-surface invariants about mutation: the gate, and the annotations.

The gate: every mutating tool must refuse to run in read-only mode. This is the
load-bearing safety property: someone can point an agent at their cloud account
and trust that nothing changes until they opt in. A single tool that forgets
`require_write` silently breaks that promise, and the failure is invisible until
something is already deleted.

The annotations: a client uses them to decide what to run without asking. They
are static per tool, so a tool that dispatches several verbs can only tell the
truth by describing the worst verb it accepts.

Rather than spot-checking known tools, these enumerate the live tool surface
and assert the invariants over everything they apply to — so a tool added later
is covered without anyone remembering to add a test.
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


# Verbs a tool may not describe as harmless, whatever else its enum admits.
# `cancel` throws away in-flight work and cannot be undone; `restart` and
# `delete` change the resource differently on each call rather than converging
# on a state, so neither is idempotent. Extend this when a new verb is added.
_UNSAFE_DISPATCH_VERBS = frozenset({"cancel", "delete", "restart"})


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


async def test_verb_dispatchers_annotate_their_most_dangerous_verb() -> None:
    """A tool that dispatches several verbs still gets exactly one annotation set.

    MCP annotations are per tool, not per argument, so a client deciding what to
    auto-approve applies them to every call it routes through that tool. A tool
    whose enum admits a destructive or non-idempotent verb therefore has to
    advertise the worst case, even though most of its verbs are benign —
    under-claiming here is what turns into an unprompted call.
    """
    app = _build_app()
    tools = [t.to_mcp_tool() for t in await app.list_tools()]

    dispatchers: list[tuple[Any, str, list[str]]] = []
    for tool in tools:
        for param, spec in ((tool.inputSchema or {}).get("properties") or {}).items():
            unsafe = sorted(set(spec.get("enum") or ()) & _UNSAFE_DISPATCH_VERBS)
            if unsafe:
                dispatchers.append((tool, param, unsafe))

    assert dispatchers, (
        "no verb dispatcher found on the tool surface; nebius_resource_action was "
        "one, so either the enum vocabulary moved or this test now checks nothing"
    )

    for tool, param, unsafe in dispatchers:
        annotations = tool.annotations
        assert annotations is not None, f"{tool.name} has no annotations"
        assert annotations.readOnlyHint is False, (
            f"{tool.name} accepts {param}={unsafe} but claims readOnlyHint=True"
        )
        assert annotations.destructiveHint is True, (
            f"{tool.name} accepts {param}={unsafe} but is annotated destructiveHint=False, "
            "so a client that auto-approves non-destructive tools would run it unprompted"
        )
        assert annotations.idempotentHint is False, (
            f"{tool.name} accepts {param}={unsafe} but is annotated idempotentHint=True, "
            "so a client would believe retrying the call is free"
        )


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

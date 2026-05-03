"""Smoke tests for the FastMCP server bootstrap."""

from __future__ import annotations

import pytest
from fastmcp import Client

from nebius_mcp.server import _build_app, is_write_mode


def test_app_builds() -> None:
    app = _build_app()
    assert app.name == "nebius-mcp"
    assert app.version == "0.1.0"


@pytest.mark.asyncio
async def test_ping_tool() -> None:
    app = _build_app()
    async with Client(app) as client:
        tools = await client.list_tools()
        names = [t.name for t in tools]
        assert "ping" in names

        result = await client.call_tool("ping", {})
        assert result.data == "pong"


def test_default_mode_is_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEBIUS_MCP_MODE", raising=False)
    assert is_write_mode() is False


def test_write_mode_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    assert is_write_mode() is True

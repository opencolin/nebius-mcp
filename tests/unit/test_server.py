"""Smoke tests for the FastMCP server bootstrap."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp import Client

from nebius_mcp.server import _build_app, is_write_mode


def main_argv(argv: list[str]) -> None:
    """Run the console entry point with a given argv."""
    import sys

    from nebius_mcp.server import main

    old = sys.argv
    sys.argv = ["nebius-mcp", *argv]
    try:
        main()
    finally:
        sys.argv = old


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


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """--version must not start a server; argparse exits 0."""
    from nebius_mcp import __version__
    from nebius_mcp.server import main

    with pytest.raises(SystemExit) as excinfo:
        main_argv(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out
    assert main is not None


def test_cli_check_prints_report_and_exits_nonzero_without_creds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--check is the documented way to debug setup without an MCP client."""
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    monkeypatch.setattr("nebius_mcp.auth.DEFAULT_CONFIG_PATH", tmp_path / "missing.yaml")

    with pytest.raises(SystemExit) as excinfo:
        main_argv(["--check"])
    assert excinfo.value.code == 1

    out = capsys.readouterr()
    report = json.loads(out.out)
    assert report["has_credentials"] is False
    assert report["mode"] == "read"
    assert report["next_steps"]

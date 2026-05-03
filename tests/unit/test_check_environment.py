"""Tests for the check_environment preflight tool."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client

from nebius_mcp.server import _build_app


@pytest.mark.asyncio
async def test_check_environment_no_creds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    monkeypatch.delenv("NEBIUS_MCP_MODE", raising=False)
    monkeypatch.setattr("nebius_mcp.auth.DEFAULT_CONFIG_PATH", tmp_path / "missing.yaml")

    app = _build_app()
    async with Client(app) as client:
        result = await client.call_tool("check_environment", {})

    report = result.data
    assert report.mode == "read"
    assert report.has_credentials is False
    assert report.credentials.iam_token_env_set is False
    assert report.credentials.config_file_exists is False
    assert any("NEBIUS_IAM_TOKEN" in step for step in report.next_steps)


@pytest.mark.asyncio
async def test_check_environment_with_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-xyz")
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    monkeypatch.setattr("nebius_mcp.auth.DEFAULT_CONFIG_PATH", tmp_path / "missing.yaml")

    app = _build_app()
    async with Client(app) as client:
        result = await client.call_tool("check_environment", {})

    report = result.data
    assert report.mode == "write"
    assert report.has_credentials is True
    assert report.credentials.iam_token_env_set is True


@pytest.mark.asyncio
async def test_check_environment_warns_when_no_parent_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: minimal\n"
        "profiles:\n"
        "  minimal:\n"
        "    endpoint: api.eu.nebius.cloud\n"
        "    auth-type: federation\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    monkeypatch.setattr("nebius_mcp.auth.DEFAULT_CONFIG_PATH", cfg)

    app = _build_app()
    async with Client(app) as client:
        result = await client.call_tool("check_environment", {})

    report = result.data
    assert report.has_credentials is True
    assert report.credentials.active_profile == "minimal"
    assert report.credentials.parent_id is None
    assert any("parent-id" in step for step in report.next_steps)

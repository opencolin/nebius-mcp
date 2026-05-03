"""Tests for the dry_run/confirm machinery."""

from __future__ import annotations

import pytest

from nebius_mcp.confirm import (
    consume,
    issue,
    preview_or_execute,
    require_write,
    reset,
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    reset()
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")


def test_token_is_single_use() -> None:
    ticket = issue("compute_delete_instance", {"id": "i-1"})
    assert consume("compute_delete_instance", {"id": "i-1"}, ticket.token) is True
    assert consume("compute_delete_instance", {"id": "i-1"}, ticket.token) is False


def test_token_bound_to_tool_name() -> None:
    ticket = issue("compute_delete_instance", {"id": "i-1"})
    assert consume("compute_delete_disk", {"id": "i-1"}, ticket.token) is False


def test_token_bound_to_args_hash() -> None:
    ticket = issue("compute_delete_instance", {"id": "i-1"})
    assert consume("compute_delete_instance", {"id": "i-2"}, ticket.token) is False


def test_token_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    ticket = issue("x", {"k": "v"}, ttl=1)
    monkeypatch.setattr("nebius_mcp.confirm.time.time", lambda: ticket.expires_at + 5)
    assert consume("x", {"k": "v"}, ticket.token) is False


def test_preview_or_execute_returns_preview_first() -> None:
    out = preview_or_execute(
        tool="compute_delete_instance",
        args={"id": "i-1"},
        confirm_token=None,
        preview={"action": "delete", "id": "i-1"},
    )
    assert isinstance(out, dict)
    assert "confirm_token" in out
    assert out["preview"]["id"] == "i-1"


def test_preview_or_execute_consumes_valid_token() -> None:
    first = preview_or_execute(
        tool="compute_delete_instance",
        args={"id": "i-1"},
        confirm_token=None,
        preview={"action": "delete"},
    )
    assert isinstance(first, dict)
    token = first["confirm_token"]

    second = preview_or_execute(
        tool="compute_delete_instance",
        args={"id": "i-1"},
        confirm_token=token,
        preview={"action": "delete"},
    )
    assert second is None  # caller proceeds


def test_preview_or_execute_rejects_wrong_args(monkeypatch: pytest.MonkeyPatch) -> None:
    first = preview_or_execute(
        tool="compute_delete_instance",
        args={"id": "i-1"},
        confirm_token=None,
        preview={},
    )
    assert isinstance(first, dict)
    token = first["confirm_token"]

    # token issued for i-1 must not be reusable for i-2
    second = preview_or_execute(
        tool="compute_delete_instance",
        args={"id": "i-2"},
        confirm_token=token,
        preview={},
    )
    assert isinstance(second, dict)  # got fresh preview, not None


def test_require_write_in_read_mode_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastmcp.exceptions import ToolError

    monkeypatch.setenv("NEBIUS_MCP_MODE", "read")
    with pytest.raises(ToolError) as ei:
        require_write("compute_delete_instance")
    assert "write mode is disabled" in str(ei.value)


def test_require_write_in_write_mode_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    require_write("compute_delete_instance")  # no exception

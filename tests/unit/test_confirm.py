"""Tests for the dry_run/confirm machinery."""

from __future__ import annotations

import pytest

from nebius_mcp.audit import _call_flags, call_scope
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


def test_preview_reports_itself_to_the_surrounding_scope() -> None:
    """`preview_or_execute` is the only code that knows which path it took."""
    with call_scope() as flags:
        assert flags.previewed is False
        preview_or_execute(
            tool="compute_delete_instance",
            args={"id": "i-1"},
            confirm_token=None,
            preview={},
        )
        assert flags.previewed is True


def test_executing_does_not_report_a_preview() -> None:
    with call_scope() as first_flags:
        first = preview_or_execute(
            tool="compute_delete_instance",
            args={"id": "i-1"},
            confirm_token=None,
            preview={},
        )
    assert isinstance(first, dict)
    assert first_flags.previewed is True

    with call_scope() as second_flags:
        second = preview_or_execute(
            tool="compute_delete_instance",
            args={"id": "i-1"},
            confirm_token=first["confirm_token"],
            preview={},
        )
    assert second is None
    assert second_flags.previewed is False


def test_a_refused_token_reports_a_preview() -> None:
    """A confirm that does not match re-previews, and is a preview in the log too."""
    with call_scope():
        first = preview_or_execute(
            tool="compute_delete_instance", args={"id": "i-1"}, confirm_token=None, preview={}
        )
    assert isinstance(first, dict)

    with call_scope() as flags:
        second = preview_or_execute(
            tool="compute_delete_instance",
            args={"id": "i-2"},  # token was issued for i-1
            confirm_token=first["confirm_token"],
            preview={},
        )
    assert isinstance(second, dict)
    assert flags.previewed is True


def test_previewing_outside_a_scope_is_a_no_op() -> None:
    """The report is not a control: nothing about the gate depends on being heard."""
    out = preview_or_execute(
        tool="compute_delete_instance", args={"id": "i-1"}, confirm_token=None, preview={}
    )
    assert isinstance(out, dict)
    assert "confirm_token" in out

    # And the unheard report left nothing behind for the next scope to find.
    with call_scope() as flags:
        assert flags.previewed is False


def test_a_scope_uninstalls_itself_and_restores_the_enclosing_one() -> None:
    """Leaving a scope must put the context back exactly as it was found.

    Reads the ContextVar directly because that is the thing being asserted:
    a scope that never resets is invisible from the outside until some later
    call marks a preview into a cell nobody is holding any more.
    """
    assert _call_flags.get() is None

    with call_scope() as outer:
        assert _call_flags.get() is outer
        preview_or_execute(
            tool="compute_delete_instance", args={"id": "i-1"}, confirm_token=None, preview={}
        )
        with call_scope() as inner:
            assert inner is not outer
            assert inner.previewed is False
        assert _call_flags.get() is outer
        assert outer.previewed is True

    assert _call_flags.get() is None


def test_scope_is_cleared_when_the_call_raises() -> None:
    """A tool that previews and then blows up must not leave the flag set."""
    with pytest.raises(RuntimeError), call_scope():
        preview_or_execute(
            tool="compute_delete_instance", args={"id": "i-1"}, confirm_token=None, preview={}
        )
        raise RuntimeError("boom")

    with call_scope() as flags:
        assert flags.previewed is False


def test_require_write_in_read_mode_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastmcp.exceptions import ToolError

    monkeypatch.setenv("NEBIUS_MCP_MODE", "read")
    with pytest.raises(ToolError) as ei:
        require_write("compute_delete_instance")
    assert "write mode is disabled" in str(ei.value)


def test_require_write_in_write_mode_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    require_write("compute_delete_instance")  # no exception

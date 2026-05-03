"""End-to-end-ish tests for the destructive-tool flow.

Verifies that:
- a destructive tool refuses without write mode
- in write mode, calling without confirm_token returns a preview + token
- calling again with a matching token executes the underlying SDK call
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp import Client

from nebius_mcp.client import reset_clients
from nebius_mcp.confirm import reset
from nebius_mcp.server import _build_app


@pytest.fixture(autouse=True)
def _setup(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_clients()
    reset()
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)


def _async_returns(value: Any) -> Any:
    async def coro() -> Any:
        return value

    return coro()


def _fake_op() -> MagicMock:
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
    return op


@pytest.fixture
def mock_compute_service(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the compute service factory with a mock that captures calls."""
    from nebius.api.nebius.compute.v1 import InstanceServiceClient

    client_mock = MagicMock()
    client_mock.delete = MagicMock(return_value=_async_returns(_fake_op()))

    registry: dict[type, MagicMock] = {InstanceServiceClient: client_mock}

    def fake_service(cls: type) -> Any:
        return registry[cls]

    monkeypatch.setattr("nebius_mcp.tools.compute.service", fake_service)
    monkeypatch.setattr("nebius_mcp.tools._ops_helpers.service", fake_service)
    return client_mock


@pytest.mark.asyncio
async def test_delete_refuses_without_write_mode(
    monkeypatch: pytest.MonkeyPatch, mock_compute_service: MagicMock
) -> None:
    monkeypatch.delenv("NEBIUS_MCP_MODE", raising=False)
    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(Exception) as ei:
            await c.call_tool("compute_delete_instance", {"id": "computeinstance-1"})
    assert "write mode is disabled" in str(ei.value)


@pytest.mark.asyncio
async def test_delete_dry_run_returns_token(
    monkeypatch: pytest.MonkeyPatch, mock_compute_service: MagicMock
) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("compute_delete_instance", {"id": "computeinstance-1"})
    assert "confirm_token" in result.data
    assert "preview" in result.data
    # The mock's delete should NOT have been called (dry run)
    assert mock_compute_service.delete.call_count == 0


@pytest.mark.asyncio
async def test_delete_with_confirm_token_executes(
    monkeypatch: pytest.MonkeyPatch, mock_compute_service: MagicMock
) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    app = _build_app()
    async with Client(app) as c:
        first = await c.call_tool("compute_delete_instance", {"id": "computeinstance-1"})
        token = first.data["confirm_token"]
        result = await c.call_tool(
            "compute_delete_instance",
            {"id": "computeinstance-1", "confirm_token": token},
        )
    assert mock_compute_service.delete.call_count == 1
    payload = result.data["data"]
    assert payload["operation_id"] == "operation-xxx"
    assert payload["successful"] is True


@pytest.mark.asyncio
async def test_state_change_refuses_without_write_mode(
    monkeypatch: pytest.MonkeyPatch, mock_compute_service: MagicMock
) -> None:
    monkeypatch.delenv("NEBIUS_MCP_MODE", raising=False)
    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(Exception) as ei:
            await c.call_tool("compute_start_instance", {"id": "computeinstance-1"})
    assert "write mode is disabled" in str(ei.value)

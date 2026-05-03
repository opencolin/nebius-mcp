"""Tests for IAM read tools.

These tests mock the Nebius service clients via ``nebius_mcp.client.service``,
verifying request shaping, pagination clamp, parent_id fallback, sanitization,
and error mapping — without contacting real Nebius infrastructure.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp import Client

from nebius_mcp.client import reset_clients
from nebius_mcp.server import _build_app


@pytest.fixture(autouse=True)
def _no_real_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_clients()
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")  # so resolve_credentials.has_any
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)


def _wrapper_for(items: list[Any], next_token: str | None = None) -> Any:
    """Build a fake list-response that looks enough like the SDK's wrapped proto."""
    resp = MagicMock()
    resp.items = items
    resp.next_page_token = next_token
    return resp


def _fake_proto(payload: dict[str, Any]) -> Any:
    """A fake wrapped proto that ``safe_proto`` can serialize.

    safe_proto reads ``__dict__['__pb2_message__']`` and runs MessageToDict on it.
    For testing we substitute a small wrapper whose serialization is just
    payload itself.
    """

    class _Fake:
        def __init__(self, p: dict[str, Any]) -> None:
            self._payload = p

    inst = _Fake(payload)
    return inst


@pytest.fixture
def mock_service(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace nebius_mcp.client.service with a registry that returns Mocks per class."""
    registry: dict[type, MagicMock] = {}

    def fake_service(cls: type) -> Any:
        if cls not in registry:
            registry[cls] = MagicMock()
        return registry[cls]

    monkeypatch.setattr("nebius_mcp.client.service", fake_service)
    monkeypatch.setattr("nebius_mcp.tools.iam.service", fake_service)
    monkeypatch.setattr("nebius_mcp.tools.compute.service", fake_service)
    return registry


@pytest.fixture
def patch_proto(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make safe_proto a passthrough so we can return plain dicts from mocks."""

    def fake_safe_proto(message: Any) -> dict[str, Any]:
        # In tests we already pass plain dicts; just redact and return.
        from nebius_mcp.sanitize import redact

        if hasattr(message, "_payload"):
            return redact(message._payload)
        return redact(message)

    monkeypatch.setattr("nebius_mcp.sanitize.safe_proto", fake_safe_proto)
    monkeypatch.setattr("nebius_mcp.tools.iam.safe_proto", fake_safe_proto)
    monkeypatch.setattr("nebius_mcp.tools.compute.safe_proto", fake_safe_proto)


@pytest.mark.asyncio
async def test_iam_whoami_returns_envelope(mock_service: dict, patch_proto: None) -> None:
    from nebius.api.nebius.iam.v1 import ProfileServiceClient

    client_mock = MagicMock()
    client_mock.get = MagicMock(
        return_value=_async_returns(_fake_proto({"user_profile": {"id": "u-1", "email": "x@y"}}))
    )
    mock_service[ProfileServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("iam_whoami", {})

    assert "_preamble" in result.data
    assert result.data["data"]["user_profile"]["id"] == "u-1"


@pytest.mark.asyncio
async def test_iam_list_projects_clamps_page_size(mock_service: dict, patch_proto: None) -> None:
    from nebius.api.nebius.iam.v2 import ListProjectsRequest, ProjectServiceClient

    captured = {}

    def fake_list(req: ListProjectsRequest) -> Any:
        captured["page_size"] = req.page_size
        captured["parent_id"] = req.parent_id
        return _async_returns(_wrapper_for([_fake_proto({"id": "p-1"})], next_token="nxt"))

    client_mock = MagicMock()
    client_mock.list = fake_list
    mock_service[ProjectServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "iam_list_projects", {"parent_id": "tenant-x", "page_size": 99999}
        )

    assert captured["parent_id"] == "tenant-x"
    assert captured["page_size"] == 200  # HARD_PAGE_LIMIT
    assert result.data["data"]["items"] == [{"id": "p-1"}]
    assert result.data["data"]["next_page_token"] == "nxt"


@pytest.mark.asyncio
async def test_iam_list_projects_no_parent_returns_empty(mock_service: dict) -> None:
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("iam_list_projects", {})
    # No parent_id supplied AND no parent-id in profile (we set token only).
    assert result.data["data"]["items"] == []
    assert "_note" in result.data


@pytest.mark.asyncio
async def test_iam_get_project_maps_id(mock_service: dict, patch_proto: None) -> None:
    from nebius.api.nebius.iam.v2 import GetProjectRequest, ProjectServiceClient

    captured: dict[str, str] = {}

    def fake_get(req: GetProjectRequest) -> Any:
        captured["id"] = req.id
        return _async_returns(_fake_proto({"id": req.id, "name": "the-project"}))

    client_mock = MagicMock()
    client_mock.get = fake_get
    mock_service[ProjectServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("iam_get_project", {"id": "project-abc"})

    assert captured["id"] == "project-abc"
    assert result.data["data"]["name"] == "the-project"


@pytest.mark.asyncio
async def test_iam_get_project_maps_sdk_error(mock_service: dict) -> None:
    from nebius.api.nebius.iam.v2 import ProjectServiceClient

    async def fail() -> None:
        raise RuntimeError("Project not found")

    client_mock = MagicMock()
    client_mock.get = MagicMock(return_value=fail())
    mock_service[ProjectServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(Exception) as ei:
            await c.call_tool("iam_get_project", {"id": "project-missing"})

    assert "NebiusAPIError" in str(ei.value)


def _async_returns(value: Any) -> Any:
    """Return an awaitable that resolves to ``value`` — emulates Nebius Request."""

    async def coro() -> Any:
        return value

    return coro()

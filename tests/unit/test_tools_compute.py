"""Tests for Compute read tools."""

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
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)


def _async_returns(value: Any) -> Any:
    async def coro() -> Any:
        return value

    return coro()


def _wrapper_for(items: list[Any], next_token: str | None = None) -> Any:
    resp = MagicMock()
    resp.items = items
    resp.next_page_token = next_token
    return resp


def _fake_proto(payload: dict[str, Any]) -> Any:
    class _Fake:
        def __init__(self, p: dict[str, Any]) -> None:
            self._payload = p

    return _Fake(payload)


@pytest.fixture
def mock_service(monkeypatch: pytest.MonkeyPatch) -> dict[type, MagicMock]:
    registry: dict[type, MagicMock] = {}

    def fake_service(cls: type) -> Any:
        if cls not in registry:
            registry[cls] = MagicMock()
        return registry[cls]

    monkeypatch.setattr("nebius_mcp.tools.compute.service", fake_service)
    return registry


@pytest.fixture
def patch_proto(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_safe_proto(message: Any) -> dict[str, Any]:
        from nebius_mcp.sanitize import redact

        if hasattr(message, "_payload"):
            return redact(message._payload)
        return redact(message)

    monkeypatch.setattr("nebius_mcp.tools.compute.safe_proto", fake_safe_proto)


@pytest.mark.asyncio
async def test_list_instances_uses_explicit_parent(mock_service: dict, patch_proto: None) -> None:
    from nebius.api.nebius.compute.v1 import InstanceServiceClient, ListInstancesRequest

    captured = {}

    def fake_list(req: ListInstancesRequest) -> Any:
        captured["parent_id"] = req.parent_id
        captured["page_size"] = req.page_size
        return _async_returns(_wrapper_for([_fake_proto({"id": "i-1"})]))

    client_mock = MagicMock()
    client_mock.list = fake_list
    mock_service[InstanceServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "compute_list_instances", {"parent_id": "project-explicit", "page_size": 5}
        )

    assert captured["parent_id"] == "project-explicit"
    assert captured["page_size"] == 5
    assert result.data["data"]["parent_id"] == "project-explicit"
    assert result.data["data"]["items"] == [{"id": "i-1"}]


@pytest.mark.asyncio
async def test_list_instances_uses_profile_parent(
    mock_service: dict, patch_proto: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: dev\nprofiles:\n  dev:\n    parent-id: project-from-profile\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("nebius_mcp.auth.DEFAULT_CONFIG_PATH", cfg)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)

    from nebius.api.nebius.compute.v1 import InstanceServiceClient, ListInstancesRequest

    captured = {}

    def fake_list(req: ListInstancesRequest) -> Any:
        captured["parent_id"] = req.parent_id
        return _async_returns(_wrapper_for([]))

    client_mock = MagicMock()
    client_mock.list = fake_list
    mock_service[InstanceServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("compute_list_instances", {})

    assert captured["parent_id"] == "project-from-profile"
    assert result.data["data"]["parent_id"] == "project-from-profile"


@pytest.mark.asyncio
async def test_list_instances_no_parent_returns_empty(mock_service: dict) -> None:
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("compute_list_instances", {})
    assert result.data["data"]["items"] == []
    assert "_note" in result.data


@pytest.mark.asyncio
async def test_get_instance(mock_service: dict, patch_proto: None) -> None:
    from nebius.api.nebius.compute.v1 import GetInstanceRequest, InstanceServiceClient

    captured = {}

    def fake_get(req: GetInstanceRequest) -> Any:
        captured["id"] = req.id
        return _async_returns(_fake_proto({"id": req.id, "name": "vm-x"}))

    client_mock = MagicMock()
    client_mock.get = fake_get
    mock_service[InstanceServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("compute_get_instance", {"id": "computeinstance-abc"})

    assert captured["id"] == "computeinstance-abc"
    assert result.data["data"]["name"] == "vm-x"


@pytest.mark.asyncio
async def test_list_disks_with_filter(mock_service: dict, patch_proto: None) -> None:
    from nebius.api.nebius.compute.v1 import DiskServiceClient, ListDisksRequest

    captured = {}

    def fake_list(req: ListDisksRequest) -> Any:
        captured["parent_id"] = req.parent_id
        captured["filter"] = req.filter
        return _async_returns(_wrapper_for([_fake_proto({"id": "d-1"})]))

    client_mock = MagicMock()
    client_mock.list = fake_list
    mock_service[DiskServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "compute_list_disks", {"parent_id": "project-1", "filter": "name='disk-x'"}
        )

    assert captured["filter"] == "name='disk-x'"
    assert result.data["data"]["items"] == [{"id": "d-1"}]


@pytest.mark.asyncio
async def test_list_platforms(mock_service: dict, patch_proto: None) -> None:
    from nebius.api.nebius.compute.v1 import ListPlatformsRequest, PlatformServiceClient

    captured = {}

    def fake_list(req: ListPlatformsRequest) -> Any:
        captured["parent_id"] = req.parent_id
        return _async_returns(
            _wrapper_for([_fake_proto({"name": "cpu-d3"}), _fake_proto({"name": "gpu-h100"})])
        )

    client_mock = MagicMock()
    client_mock.list = fake_list
    mock_service[PlatformServiceClient] = client_mock

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("compute_list_platforms", {"parent_id": "tenant-1"})

    assert captured["parent_id"] == "tenant-1"
    items = result.data["data"]["items"]
    assert {"name": "cpu-d3"} in items
    assert {"name": "gpu-h100"} in items

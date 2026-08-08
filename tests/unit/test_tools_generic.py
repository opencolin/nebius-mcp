"""Tests for the generic nebius_resource_* tools."""

from __future__ import annotations

import json
from collections import defaultdict
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


def _async(value: Any) -> Any:
    async def coro() -> Any:
        return value

    return coro()


@pytest.fixture
def mock_service(monkeypatch: pytest.MonkeyPatch) -> defaultdict[type, MagicMock]:
    # defaultdict so a test can stub a client before the tool first requests it.
    registry: defaultdict[type, MagicMock] = defaultdict(MagicMock)
    monkeypatch.setattr("nebius_mcp.tools.generic.service", lambda cls: registry[cls])
    return registry


@pytest.fixture
def patch_proto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("nebius_mcp.tools.generic.safe_proto", lambda m: {"ok": True})


def _payload(result: Any) -> Any:
    return json.loads(result.content[0].text)


async def test_list_resource_types_covers_new_domains() -> None:
    app = _build_app()
    async with Client(app) as c:
        data = _payload(await c.call_tool("nebius_list_resource_types", {}))["data"]
    keys = {r["resource_type"] for r in data["resource_types"]}
    # Domains that had no tools at all before the generic layer.
    for expected in ("storage.bucket", "dns.zone", "kms.symmetric_key", "quotas.allowance"):
        assert expected in keys
    assert data["count"] == len(keys)


async def test_list_resource_types_filters_by_domain() -> None:
    app = _build_app()
    async with Client(app) as c:
        data = _payload(await c.call_tool("nebius_list_resource_types", {"domain": "dns"}))["data"]
    assert {r["resource_type"] for r in data["resource_types"]} == {"dns.zone", "dns.record"}


async def test_resource_list_passes_parent_and_returns_items(
    mock_service: defaultdict[type, MagicMock], patch_proto: None
) -> None:
    from nebius.api.nebius.storage.v1 import BucketServiceClient

    resp = MagicMock()
    resp.items = [MagicMock()]
    resp.next_page_token = "next"
    mock_service[BucketServiceClient].list.return_value = _async(resp)

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "nebius_resource_list",
            {"resource_type": "storage.bucket", "parent_id": "project-abc"},
        )
    data = _payload(result)["data"]
    assert data["resource_type"] == "storage.bucket"
    assert data["items"] == [{"ok": True}]
    assert data["next_page_token"] == "next"

    sent = mock_service[BucketServiceClient].list.call_args[0][0]
    assert sent.parent_id == "project-abc"
    assert sent.page_size == 50


async def test_resource_list_without_parent_explains_requirement(
    mock_service: defaultdict[type, MagicMock],
) -> None:
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("nebius_resource_list", {"resource_type": "mk8s.node_group"})
    body = _payload(result)
    assert body["data"]["items"] == []
    # The note must name the real parent so the model can self-correct.
    assert "CLUSTER" in body["_note"]


async def test_resource_get_uses_id(
    mock_service: defaultdict[type, MagicMock], patch_proto: None
) -> None:
    from nebius.api.nebius.dns.v1 import ZoneServiceClient

    mock_service[ZoneServiceClient].get.return_value = _async(MagicMock())
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "nebius_resource_get", {"resource_type": "dns.zone", "id": "zone-1"}
        )
    assert _payload(result)["data"]["resource"] == {"ok": True}
    assert mock_service[ZoneServiceClient].get.call_args[0][0].id == "zone-1"


async def test_unsupported_verb_reports_available_operations() -> None:
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "nebius_resource_delete",
            {"resource_type": "compute.platform", "id": "x"},
            raise_on_error=False,
        )
    assert result.is_error
    text = result.content[0].text
    assert "does not support 'delete'" in text
    assert "Available operations" in text


async def test_delete_requires_write_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEBIUS_MCP_MODE", raising=False)
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "nebius_resource_delete",
            {"resource_type": "storage.bucket", "id": "bucket-1"},
            raise_on_error=False,
        )
    assert result.is_error
    assert "write mode is disabled" in result.content[0].text


async def test_delete_is_two_step_in_write_mode(
    monkeypatch: pytest.MonkeyPatch, mock_service: defaultdict[type, MagicMock]
) -> None:
    from nebius.api.nebius.storage.v1 import BucketServiceClient

    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    app = _build_app()
    async with Client(app) as c:
        first = _payload(
            await c.call_tool(
                "nebius_resource_delete",
                {"resource_type": "storage.bucket", "id": "bucket-1"},
            )
        )
    # Dry run must not touch the API.
    assert mock_service[BucketServiceClient].delete.call_count == 0
    assert first["confirm_token"]
    assert "NOT executed" in first["_preamble"]


async def test_action_requires_write_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEBIUS_MCP_MODE", raising=False)
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "nebius_resource_action",
            {"resource_type": "ai.endpoint", "action": "stop", "id": "e-1"},
            raise_on_error=False,
        )
    assert result.is_error
    assert "write mode is disabled" in result.content[0].text

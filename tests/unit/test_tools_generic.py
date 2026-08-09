"""Tests for the generic nebius_resource_* tools."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp import Client

from nebius_mcp import catalog
from nebius_mcp.client import reset_clients
from nebius_mcp.server import _build_app
from nebius_mcp.tools import generic


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


async def test_unsupported_verb_reports_available_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
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


def _withheld(verb: str) -> str | None:
    """A resource whose SDK exposes ``verb`` but whose request we cannot build.

    Derived from the installed SDK rather than named, so the test tracks the
    SDK instead of pinning today's eight known pairs.
    """
    for spec in catalog.RESOURCES:
        if verb in catalog.sdk_verbs(spec.key) and not catalog.supports(spec.key, verb):
            return spec.key
    return None


async def test_unbuildable_verb_is_not_reported_as_unsupported(
    monkeypatch: pytest.MonkeyPatch, mock_service: defaultdict[type, MagicMock]
) -> None:
    """Reporting this as an unsupported verb would be false: the RPC exists.

    What is missing is a way to express the request with a single string id, and
    the message has to distinguish those so the caller stops looking for a typo.
    """
    resource_type = _withheld("delete")
    if resource_type is None:  # pragma: no cover - true of every SDK shipped so far
        pytest.skip("installed SDK builds every delete request from an id")

    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "nebius_resource_delete",
            {"resource_type": resource_type, "id": "x"},
            raise_on_error=False,
        )
    assert result.is_error
    text = result.content[0].text
    assert "does not support" not in text
    assert "not reachable through the generic tools" in text
    # The SDK's own construction error names the offending field or type.
    assert "TypeError" in text
    # Rejected before any token was minted or any client was touched.
    assert "confirm_token" not in text
    assert not mock_service[catalog.client_class(resource_type)].delete.called


async def test_unbuildable_action_is_rejected_before_execution(
    monkeypatch: pytest.MonkeyPatch, mock_service: defaultdict[type, MagicMock]
) -> None:
    candidates = [(v, _withheld(v)) for v in generic._ACTIONS]
    pair = next(((v, k) for v, k in candidates if k is not None), None)
    if pair is None:  # pragma: no cover - true of every SDK shipped so far
        pytest.skip("installed SDK builds every action request from an id")
    action, resource_type = pair

    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "nebius_resource_action",
            {"resource_type": resource_type, "action": action, "id": "x"},
            raise_on_error=False,
        )
    assert result.is_error
    assert "not reachable through the generic tools" in result.content[0].text
    assert not getattr(mock_service[catalog.client_class(resource_type)], action).called


async def test_list_resource_types_hides_unbuildable_operations() -> None:
    """The advertisement and the error message must agree about what works."""
    app = _build_app()
    async with Client(app) as c:
        data = _payload(await c.call_tool("nebius_list_resource_types", {}))["data"]
    advertised = {r["resource_type"]: set(r["operations"]) for r in data["resource_types"]}
    for spec in catalog.RESOURCES:
        withheld = catalog.sdk_verbs(spec.key) - catalog.verbs(spec.key)
        assert not (advertised[spec.key] & withheld), spec.key


def test_dedicated_tool_hint_names_a_tool_when_one_exists() -> None:
    hint = generic._dedicated_tool_hint("compute.instance")
    assert "compute_delete_instance" in hint


def test_dedicated_tool_hint_says_so_when_nothing_covers_the_resource() -> None:
    hint = generic._dedicated_tool_hint("iam.access_key")
    assert "No dedicated tool" in hint


async def test_dedicated_tool_hints_name_real_tools() -> None:
    """Pointing at a tool that does not exist is worse than pointing nowhere.

    One-directional on purpose: a newly added dedicated tool that nobody mapped
    only costs a missed hint, but a stale name in the map is a wrong answer.
    """
    app = _build_app()
    async with Client(app) as c:
        registered = {t.name for t in await c.list_tools()}
    named = {name for names in generic._DEDICATED_TOOLS.values() for name in names}
    assert named <= registered, sorted(named - registered)


def test_dedicated_tool_hints_use_known_resource_types() -> None:
    assert set(generic._DEDICATED_TOOLS) <= set(catalog.BY_KEY)


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


async def test_cancel_action_requires_confirm_token(
    monkeypatch: pytest.MonkeyPatch, mock_service: defaultdict[type, MagicMock]
) -> None:
    """Cancelling a job discards work, so it takes the same gate as a delete."""
    from nebius.api.nebius.ai.v1 import JobServiceClient

    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    app = _build_app()
    async with Client(app) as c:
        first = _payload(
            await c.call_tool(
                "nebius_resource_action",
                {"resource_type": "ai.job", "action": "cancel", "id": "job-1"},
            )
        )
    assert mock_service[JobServiceClient].cancel.call_count == 0
    assert first["confirm_token"]
    assert "NOT executed" in first["_preamble"]


async def test_reversible_action_needs_no_confirm_token(
    monkeypatch: pytest.MonkeyPatch, mock_service: defaultdict[type, MagicMock]
) -> None:
    """start/stop are reversible and must not demand a round trip."""
    from nebius.api.nebius.ai.v1 import EndpointServiceClient

    op = MagicMock()
    op.wait.return_value = _async(None)
    mock_service[EndpointServiceClient].stop.return_value = _async(op)

    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    app = _build_app()
    async with Client(app) as c:
        body = _payload(
            await c.call_tool(
                "nebius_resource_action",
                {
                    "resource_type": "ai.endpoint",
                    "action": "stop",
                    "id": "e-1",
                    "wait": False,
                },
            )
        )
    assert "confirm_token" not in body
    assert mock_service[EndpointServiceClient].stop.call_count == 1

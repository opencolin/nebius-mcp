"""Gates on the one tool that returns plaintext secrets.

``secrets_reveal_payload`` is the only place in the server where secret material
leaves the account in the clear. Three independent gates guard it — write mode,
the ``NEBIUS_MCP_ALLOW_SECRET_REVEAL`` opt-in, and the confirm-token two-step —
and its annotations must keep clients from auto-approving it.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp import Client
from mcp.types import Tool as McpTool

import nebius_mcp.tools
from nebius_mcp.client import reset_clients
from nebius_mcp.confirm import reset
from nebius_mcp.server import _build_app
from nebius_mcp.tools.secrets import ALLOW_REVEAL_ENV

# Tools that return secret material without passing it through the sanitizer.
# Hard-coded on purpose: the test cross-checks this against the live tool
# surface, so adding a bypass without adding it here fails the suite, and
# listing a tool that no longer exists fails it too.
SENSITIVE_TOOLS = frozenset({"secrets_reveal_payload"})

_TOOLS_DIR = Path(nebius_mcp.tools.__file__).parent

# Redaction happens in sanitize.redact, reached through safe_proto. A tool that
# calls proto_to_dict directly has opted out of it; that is the only way raw
# secret material can reach the model.
_BYPASS = "proto_to_dict"


def _tool_functions(tree: ast.Module) -> list[tuple[str, ast.AST]]:
    """Return (tool_name, function_node) for every ``@app.tool(name=...)`` function."""
    found: list[tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for kw in decorator.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                    found.append((str(kw.value.value), node))
    return found


def _bypass_call_sites() -> tuple[dict[str, int], list[str]]:
    """Find every ``proto_to_dict`` call in ``tools/``.

    Returns the count per registered tool name, plus ``file:line`` for any call
    that is not inside a registered tool function — an unattributable bypass,
    which the test treats as a failure because it cannot be mapped to
    annotations.
    """
    per_tool: dict[str, int] = {}
    stray: list[str] = []

    for path in sorted(_TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        uses = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == _BYPASS]
        if not uses:
            continue

        attributed: set[int] = set()
        for tool_name, func in _tool_functions(tree):
            hits = [n for n in ast.walk(func) if isinstance(n, ast.Name) and n.id == _BYPASS]
            if hits:
                per_tool[tool_name] = per_tool.get(tool_name, 0) + len(hits)
                attributed.update(id(n) for n in hits)

        stray.extend(f"{path.name}:{n.lineno}" for n in uses if id(n) not in attributed)

    return per_tool, stray


async def _list_tools() -> dict[str, McpTool]:
    app = _build_app()
    return {t.name: t.to_mcp_tool() for t in await app.list_tools()}


async def test_no_read_only_tool_can_return_unredacted_secrets() -> None:
    tools = await _list_tools()

    missing = sorted(SENSITIVE_TOOLS - tools.keys())
    assert not missing, f"SENSITIVE_TOOLS names tools that are not registered: {missing}"

    per_tool, stray = _bypass_call_sites()
    assert not stray, f"{_BYPASS} called outside any registered tool: {stray}"
    assert set(per_tool) == set(SENSITIVE_TOOLS), (
        f"tools bypassing redaction: {sorted(per_tool)}; declared: {sorted(SENSITIVE_TOOLS)}"
    )

    for name in sorted(SENSITIVE_TOOLS):
        annotations = tools[name].annotations
        assert annotations is not None, f"{name} has no annotations"
        assert annotations.readOnlyHint is False, (
            f"{name} returns unredacted secret material but is annotated readOnlyHint=True, "
            "so a client on auto-approve-read-only would call it without prompting"
        )
        assert annotations.destructiveHint is True, f"{name} must be annotated destructiveHint=True"


class _FakePayload:
    """A stand-in for a MysteryBox payload message.

    ``sanitize.proto_to_dict`` takes the ``to_json`` path for SDK >= 0.4 message
    classes, so that is the only method this needs.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def to_json(self, **_: Any) -> str:
        return json.dumps(self._data)


class _ServiceSpy:
    """Records which service-client classes were constructed."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.constructed: list[type] = []
        self.client = MagicMock()
        self.client.get = MagicMock(side_effect=lambda *_a, **_k: self._returns(payload))
        self.client.get_by_key = MagicMock(side_effect=lambda *_a, **_k: self._returns(payload))

    @staticmethod
    async def _returns(payload: dict[str, Any]) -> _FakePayload:
        return _FakePayload(payload)

    def __call__(self, client_cls: type) -> Any:
        self.constructed.append(client_cls)
        return self.client


@pytest.fixture(autouse=True)
def _setup(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_clients()
    reset()
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")


@pytest.fixture
def payload_service(monkeypatch: pytest.MonkeyPatch) -> _ServiceSpy:
    spy = _ServiceSpy({"value": "s3cr3t-plaintext"})
    monkeypatch.setattr("nebius_mcp.tools.secrets.service", spy)
    return spy


def _payload_client_cls() -> type:
    from nebius.api.nebius.mysterybox.v1 import PayloadServiceClient

    return PayloadServiceClient  # type: ignore[no-any-return]


async def test_reveal_refuses_in_read_mode(payload_service: _ServiceSpy) -> None:
    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(Exception) as ei:
            await c.call_tool("secrets_reveal_payload", {"secret_id": "mysteryboxsecret-1"})

    assert "write mode is disabled" in str(ei.value)
    assert _payload_client_cls() not in payload_service.constructed


async def test_reveal_refuses_when_opt_in_is_unset(
    monkeypatch: pytest.MonkeyPatch, payload_service: _ServiceSpy
) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    monkeypatch.delenv(ALLOW_REVEAL_ENV, raising=False)

    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(Exception) as ei:
            await c.call_tool("secrets_reveal_payload", {"secret_id": "mysteryboxsecret-1"})

    assert ALLOW_REVEAL_ENV in str(ei.value)
    assert _payload_client_cls() not in payload_service.constructed
    assert payload_service.client.get.call_count == 0


async def test_reveal_dry_run_returns_token_and_calls_nothing(
    monkeypatch: pytest.MonkeyPatch, payload_service: _ServiceSpy
) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    monkeypatch.setenv(ALLOW_REVEAL_ENV, "1")

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("secrets_reveal_payload", {"secret_id": "mysteryboxsecret-1"})

    assert "confirm_token" in result.data
    assert _payload_client_cls() not in payload_service.constructed
    assert payload_service.client.get.call_count == 0
    # The preview names the secret; it must not carry the payload itself.
    assert "s3cr3t-plaintext" not in json.dumps(result.data)


async def test_reveal_with_confirm_token_returns_plaintext(
    monkeypatch: pytest.MonkeyPatch, payload_service: _ServiceSpy
) -> None:
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    monkeypatch.setenv(ALLOW_REVEAL_ENV, "1")

    app = _build_app()
    async with Client(app) as c:
        first = await c.call_tool("secrets_reveal_payload", {"secret_id": "mysteryboxsecret-1"})
        second = await c.call_tool(
            "secrets_reveal_payload",
            {"secret_id": "mysteryboxsecret-1", "confirm_token": first.data["confirm_token"]},
        )

    assert payload_service.constructed == [_payload_client_cls()]
    assert second.data["data"] == {"value": "s3cr3t-plaintext"}


async def test_opt_in_ignores_values_that_are_not_affirmative(
    monkeypatch: pytest.MonkeyPatch, payload_service: _ServiceSpy
) -> None:
    """``FOO=0`` and ``FOO=false`` must not enable the tool the way ``FOO=1`` does."""
    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")

    app = _build_app()
    for value in ("", "0", "false", "no"):
        monkeypatch.setenv(ALLOW_REVEAL_ENV, value)
        async with Client(app) as c:
            with pytest.raises(Exception) as ei:
                await c.call_tool("secrets_reveal_payload", {"secret_id": "mysteryboxsecret-1"})
        assert ALLOW_REVEAL_ENV in str(ei.value), f"{value!r} was treated as affirmative"

    assert not payload_service.constructed

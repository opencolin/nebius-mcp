"""Tests for output sanitization."""

from __future__ import annotations

import json
from typing import Any

import pytest

from nebius_mcp.sanitize import (
    DATA_PREAMBLE,
    proto_to_dict,
    redact,
    wrap,
)


# Built at runtime rather than written as literals. A committed string that
# looks like a private key trips secret scanners on every future commit that
# touches this file, and the alternative — allowlisting the file — would stop
# the scanner catching a real credential pasted here later.
def _pem(kind: str, body: str = "", terminated: bool = True) -> str:
    begin = "-" * 5 + "BEGIN " + kind + " PRIVATE KEY" + "-" * 5
    if not terminated:
        return begin + "\n" + body
    end = "-" * 5 + "END " + kind + " PRIVATE KEY" + "-" * 5
    return begin + "\n" + body + "\n" + end


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


def test_cloud_init_user_data_is_redacted() -> None:
    """Cloud-init is where provisioning secrets live.

    compute_get_instance and compute_list_instances return the instance spec
    verbatim, so anything baked into user-data at create time — API keys,
    database passwords, registry logins — would otherwise be handed straight
    to the model.
    """
    payload = {
        "spec": {
            "cloud_init_user_data": (
                "#cloud-config\n"
                "write_files:\n"
                "  - content: |\n"
                "      OPENAI_API_KEY=sk-proj-REALKEY\n"
                "      DB_PASSWORD=hunter2\n"
            )
        }
    }

    out = redact(payload)

    assert out["spec"]["cloud_init_user_data"] == "<redacted>"
    assert "sk-proj-REALKEY" not in str(out)
    assert "hunter2" not in str(out)


def test_plain_user_data_is_redacted() -> None:
    assert redact({"user_data": "SECRET"})["user_data"] == "<redacted>"


def test_ssh_public_keys_are_not_redacted() -> None:
    """Public keys are public. Over-redacting makes instance output useless."""
    out = redact({"ssh_public_key": "ssh-rsa AAAAB3NzaC1yc2E"})
    assert out["ssh_public_key"] == "ssh-rsa AAAAB3NzaC1yc2E"


_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl"

# (case id, payload handed to redact, the cleartext that must not survive).
# Half of these are key-driven and half value-driven, which is the point: a
# sanitizer that only matches keys leaks anything an API embeds in a string,
# and one that only matches values leaks every opaque blob it has no pattern
# for.
_BYPASS_CASES: tuple[tuple[str, dict[str, Any], str], ...] = (
    ("secret_key", {"secret_key": "SK-CLEARTEXT-0"}, "SK-CLEARTEXT-0"),
    ("secretKey", {"secretKey": "SK-CLEARTEXT-1"}, "SK-CLEARTEXT-1"),
    ("accessKeySecret", {"accessKeySecret": "SK-CLEARTEXT-2"}, "SK-CLEARTEXT-2"),
    (
        "cloud_init_user_data",
        {"spec": {"cloud_init_user_data": "#cloud-config\nDB_PASSWORD=SK-CLEARTEXT-3"}},
        "SK-CLEARTEXT-3",
    ),
    (
        "client_key_data",
        {"client_key_data": "LS0tLS1CRUdJTiBSU0EgUFJJSK-CLEARTEXT-4"},
        "SK-CLEARTEXT-4",
    ),
    (
        "kubeconfig",
        {"kubeconfig": "apiVersion: v1\nusers:\n- user:\n    token: SK-CLEARTEXT-5"},
        "SK-CLEARTEXT-5",
    ),
    (
        "pem_header",
        {"description": _pem("RSA", terminated=False)},
        _pem("RSA", terminated=False),
    ),
    (
        "presigned_url",
        {
            "url": (
                "https://storage.eu-north1.nebius.cloud/bucket/object"
                "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                "&X-Amz-Credential=SK-CLEARTEXT-6%2F20260808%2Feu-north1%2Fs3"
                "&X-Amz-Signature=SK-CLEARTEXT-7"
            )
        },
        "SK-CLEARTEXT-7",
    ),
    ("jwt", {"note": f"bearer {_JWT}"}, _JWT),
    # Not in the original nine. EndpointSpec.VolumeMount.S3Config.S3Credentials
    # in nebius.api.nebius.ai.v1 carries this field, and ai_get_endpoint returns
    # the spec, so a plaintext S3 secret reached the model until the substring
    # rule stopped requiring a leading separator.
    ("secret_access_key", {"secret_access_key": "SK-CLEARTEXT-8"}, "SK-CLEARTEXT-8"),
)


@pytest.mark.parametrize(
    ("payload", "cleartext"),
    [(payload, cleartext) for _, payload, cleartext in _BYPASS_CASES],
    ids=[case_id for case_id, _, _ in _BYPASS_CASES],
)
def test_known_redaction_bypasses_are_closed(payload: dict[str, Any], cleartext: str) -> None:
    """Each of these reached the model in the clear at some point in this repo's history."""
    out = json.dumps(redact(payload))

    assert "<redacted>" in out
    assert cleartext not in out


def test_presigned_url_keeps_its_object_path() -> None:
    """Redact the signature, not the whole URL.

    The bucket and object path are what make a storage error diagnosable, and
    a presigned URL without its signature cannot be replayed.
    """
    url = "https://storage.eu-north1.nebius.cloud/bucket/object?X-Amz-Signature=abcdef0123456789"
    out = redact({"url": url})

    assert out["url"].startswith("https://storage.eu-north1.nebius.cloud/bucket/object")
    assert "abcdef0123456789" not in out["url"]


def test_prose_containing_the_word_secret_is_left_alone() -> None:
    """Value matching is by pattern, never by keyword.

    Descriptions are free text. Redacting them because they contain the word
    "secret" would corrupt them silently, which is worse than leaving them
    verbose: nothing in the output signals that anything was lost.
    """
    prose = "Rotate the secret before the credential audit; the password policy is annual."
    out = redact({"description": prose, "name": "secret-rotation-runbook"})

    assert out["description"] == prose
    assert out["name"] == "secret-rotation-runbook"


def test_truncated_pem_block_is_fully_redacted() -> None:
    """A PEM block with no END marker must not leak its body.

    Truncation is not hypothetical: capped error strings and log tails are
    exactly where half a PEM shows up. The earlier pattern made the END marker
    an optional trailing group, so on a truncated block only the header
    matched and the key material after it survived.
    """
    truncated = _pem("RSA", "MIIEowIBAAKCAQEA" + "_SECRETBODY_", terminated=False)
    assert "_SECRETBODY_" not in redact({"blob": truncated})["blob"]


def test_complete_pem_block_is_redacted() -> None:
    complete = _pem("EC", "KEYBODY")
    assert "KEYBODY" not in redact({"blob": complete})["blob"]


def test_hyphenated_key_names_match() -> None:
    """Criterion 1 requires stripping hyphens as well as underscores.

    Removing "-" from the separator set previously left the suite green.
    """
    assert redact({"secret-key": "X"})["secret-key"] == "<redacted>"
    assert redact({"access-key-secret": "X"})["access-key-secret"] == "<redacted>"


def test_presigned_url_credential_parameter_is_redacted() -> None:
    """X-Amz-Credential was unasserted; narrowing the regex left the suite green."""
    url = (
        "https://bucket.example/o?X-Amz-Credential="
        + "AKIA"
        + "EXAMPLE%2F20260808&X-Amz-Expires=900"
    )
    out = redact({"url": url})["url"]
    assert "" + "AKIA" + "EXAMPLE" not in out
    assert "X-Amz-Expires=900" in out


def test_presigned_url_security_token_is_redacted() -> None:
    """An STS session token authenticates arbitrary calls on its own.

    Unlike the signature beside it, this one is a standalone credential, and it
    reaches the model through the success path — inside an endpoint, a
    description or a status string, none of which ``_is_sensitive_key`` looks
    at. It is pinned separately from ``X-Amz-Signature`` because narrowing the
    alternation to drop it would otherwise leave the suite green.
    """
    session_token = "FwoGZXIvYXdz" + "EBYaDEXAMPLESESSIONTOKEN"
    url = (
        "https://storage.eu-north1.nebius.cloud/my-bucket/logs/run-42.json"
        "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Security-Token={session_token}"
        "&X-Amz-Signature=abcdef0123456789"
    )

    out = redact({"endpoint": url})["endpoint"]

    assert session_token not in out
    assert "X-Amz-Security-Token=<redacted>" in out
    # The bucket and object path stay readable, for the same reason the
    # signature rule keeps them: a storage failure has to remain diagnosable.
    assert "my-bucket/logs/run-42.json" in out


def test_individually_required_exact_keys_match() -> None:
    """Each of these was removable without failing a test.

    None substring-matches another rule, so deleting one silently reopened a
    bypass. Assert them by name.
    """
    for key in ("client_certificate_data", "ssh_authorized_keys", "client_key_data", "kubeconfig"):
        assert redact({key: "MATERIAL"})[key] == "<redacted>", key


# (field name, value that must survive). Every one contains a substring from
# _SENSITIVE_SUBSTRINGS and holds no secret. Redacting these does not read as a
# withheld value — it reads as data the account does not have, and the model
# acts on that.
_BENIGN_FIELDS: tuple[tuple[str, object], ...] = (
    ("tokens_used", 4096),
    ("tokens_remaining", 12000),
    ("token_count", 7),
    ("total_tokens", 8192),
    ("prompt_tokens", 512),
    ("completion_tokens", 128),
    ("max_tokens", 2048),
    ("credentials_expire_at", "2026-08-10T00:00:00Z"),
    ("token_expires_at", "2026-08-10T12:00:00Z"),
    ("secret_version_count", 3),
)


@pytest.mark.parametrize(("field", "value"), _BENIGN_FIELDS, ids=[f for f, _ in _BENIGN_FIELDS])
def test_benign_neighbours_of_the_substring_rule_survive(field: str, value: object) -> None:
    assert redact({field: value})[field] == value


@pytest.mark.parametrize("field", ["tokensUsed", "tokens-used", "TOKENS_USED"])
def test_the_benign_list_is_matched_after_normalization(field: str) -> None:
    """camelCase and kebab-case reach the sanitizer too, so the exemption has to
    survive the same folding the denylist does."""
    assert redact({field: 4096})[field] == 4096


@pytest.mark.parametrize(
    "field",
    [
        "secret",
        "credential",
        "credentials",
        "access_token",
        "secretKey",
        "refresh_token",
        # not on either list: the substring rule still catches it, which is the
        # fail-closed default the benign list must not weaken
        "some_vendor_token",
        "db_password_hash",
    ],
)
def test_the_benign_list_does_not_weaken_the_denylist(field: str) -> None:
    assert redact({field: "SK-CLEARTEXT"})[field] == "<redacted>"


def test_no_name_is_on_both_lists() -> None:
    """The invariant that makes the ordering moot in practice.

    Kept separate from the ordering test below because it is the stronger
    statement: if the sets never intersect, no entry added to the benign list
    can shadow a denylisted one by accident.
    """
    from nebius_mcp import sanitize

    overlap = sanitize._NORMALIZED_SENSITIVE_KEYS & sanitize._NORMALIZED_BENIGN_KEYS
    assert not overlap, f"on both lists: {overlap}"


def test_the_exact_denylist_outranks_the_benign_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ordering, actually exercised.

    Asserting non-overlap alone does not pin the order — with disjoint sets,
    swapping the two checks is unobservable, which mutation testing showed. So
    force the overlap the real lists do not have, and assert the denylist still
    wins. Reordering `_is_sensitive_key` fails this.
    """
    from nebius_mcp import sanitize

    monkeypatch.setattr(
        sanitize,
        "_NORMALIZED_BENIGN_KEYS",
        sanitize._NORMALIZED_BENIGN_KEYS | {sanitize._normalize_key("password")},
    )

    assert sanitize._is_sensitive_key("password") is True


def test_the_benign_list_holds_no_patterns() -> None:
    """Every entry is an exact name. A pattern here is how a real credential
    eventually gets exempted by a rule nobody re-read.
    """
    from nebius_mcp import sanitize

    assert all(not any(c in name for c in "*?[") for name in sanitize._BENIGN_KEYS), (
        "benign list must contain exact names, never patterns"
    )

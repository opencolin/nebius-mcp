"""Tests for output sanitization."""

from __future__ import annotations

import json
import random
import re
import time
from typing import Any

import pytest

from nebius_mcp.sanitize import (
    DATA_PREAMBLE,
    proto_to_dict,
    redact,
    redact_text,
    wrap,
)

# Built at runtime rather than written as literals. A committed string that
# looks like a private key trips secret scanners on every future commit that
# touches this file, and the alternative — allowlisting the file — would stop
# the scanner catching a real credential pasted here later.
# Assembled, not written out. A host whose name contains "secret" followed by a
# port is exactly the false positive these corpora exist to pin — and it is also
# what gitleaks' generic-api-key rule reads as `name:secret`, which blocks the
# push. Allowlisting the file instead would stop the scanner catching a real
# credential pasted here later, so the string is built at runtime and keeps its
# shape.
_HOST_WITH_SENSITIVE_NAME = "secret" + "-store.internal" + ":8200/v1/sys/health"


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


# ---------------------------------------------------------------------------
# R-012 — a quote between the field name and its separator
# ---------------------------------------------------------------------------

# Every one of these survived verbatim before. The asymmetry R-012 records is
# that the loose human-written `secret_key: x` was caught and the well-formed
# machine-generated `{"secret_key": "x"}` was not — and the second is the one
# an API error quoting a request body actually arrives in.
_QUOTED_ASSIGNMENTS: tuple[tuple[str, str, str], ...] = (
    ("json_double", '{"secret_key": "SK-CLEARTEXT-Q0"}', "SK-CLEARTEXT-Q0"),
    ("json_single", "{'password': 'SK-CLEARTEXT-Q1'}", "SK-CLEARTEXT-Q1"),
    ("space_before_colon", '{"api_key" : "SK-CLEARTEXT-Q2"}', "SK-CLEARTEXT-Q2"),
    ("equals_separator", '{"token"="SK-CLEARTEXT-Q3"}', "SK-CLEARTEXT-Q3"),
    (
        "escaped_in_json_string",
        'detail "{\\"password\\": \\"SK-CLEARTEXT-Q4\\"}"',
        "SK-CLEARTEXT-Q4",
    ),
    ("uppercase_name", '{"PGPASSWORD": "SK-CLEARTEXT-Q5"}', "SK-CLEARTEXT-Q5"),
    ("unquoted_value", '{"client_secret": SK-CLEARTEXT-Q6}', "SK-CLEARTEXT-Q6"),
)


@pytest.mark.parametrize(
    ("text", "cleartext"),
    [(text, cleartext) for _, text, cleartext in _QUOTED_ASSIGNMENTS],
    ids=[case_id for case_id, _, _ in _QUOTED_ASSIGNMENTS],
)
def test_a_quoted_field_name_no_longer_defeats_the_assignment_rule(
    text: str, cleartext: str
) -> None:
    """R-012. Deleting ``_closing_quote_width``'s body fails every case here."""
    out = redact_text(text)

    assert cleartext not in out
    assert "<redacted>" in out


def test_a_quote_is_only_skipped_when_the_same_quote_opens_the_name() -> None:
    """The skip is anchored on both sides, so a stray quote cannot manufacture
    a match out of text that merely happens to contain one."""
    assert redact_text('he said secret": nothing') == 'he said secret": nothing'
    assert redact_text("\"secret': nothing") == "\"secret': nothing"


def test_a_redacted_value_keeps_the_quotes_it_arrived_in() -> None:
    """Two things at once, and the second is why it is not cosmetic.

    ``{"secret_key": "<redacted>"}`` is still JSON. And because the value
    alternation prefers the quoted form — which stops at the closing quote —
    over the bare form — which runs to the next separator — replacing a quoted
    value with a bare marker lets the bare form match further on the next pass.
    Without the quotes ``api_key:''trailing`` redacts one more token every time
    it goes through, and nothing else in this file notices.
    """
    assert redact_text('{"secret_key": "SK-CLEARTEXT-Q8"}') == '{"secret_key": "<redacted>"}'

    once = redact_text("api_key:''trailing")
    assert once == "api_key:'<redacted>'trailing"
    assert redact_text(once) == once


def test_r012_is_closed_on_the_error_path_only() -> None:
    """Stated so nobody reads the parametrized test above as more than it is.

    The assignment rule still runs in ``redact_text`` and not in ``redact``,
    which is what ``tests/unit/test_operation.py`` pins and what SECURITY.md's
    "Known gaps" section describes. Moving it would strip the port off
    ``token-service.internal:8443`` on every successful response — see the
    benign corpus below, where that string is unchanged by ``redact`` and
    mangled by ``redact_text`` on main and here alike.
    """
    quoted = '{"secret_key": "SK-CLEARTEXT-Q7"}'

    assert redact({"description": quoted})["description"] == quoted
    assert "SK-CLEARTEXT-Q7" not in redact_text(quoted)


# ---------------------------------------------------------------------------
# R-013 — shapes no rule named at all
# ---------------------------------------------------------------------------

# Assembled from parts for the reason the AKIA case above already is: a
# plausible-looking credential committed to a public repository is rejected by
# GitHub push protection, and allowlisting the file would stop the scanner
# catching a real one pasted here later.
_GITHUB_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
_SLACK_BOT = "xoxb-" + "123456789012" + "-" + "123456789012" + "-" + "AbCdEfGhIjKlMnOpQrStUvWx"
_AWS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"

# (case id, string, cleartext that must not survive). One entry per new value
# pattern at minimum: deleting any single pattern from
# ``_SENSITIVE_VALUE_PATTERNS`` must fail this test by name.
_UNNAMED_CREDENTIALS: tuple[tuple[str, str, str], ...] = (
    ("userinfo_postgres", "postgres://appuser:SK-CLEAR-U0@db.internal:5432/prod", "SK-CLEAR-U0"),
    ("userinfo_empty_user", "redis://:SK-CLEAR-U1@cache.internal:6379/0", "SK-CLEAR-U1"),
    ("userinfo_https", "https://svc:SK-CLEAR-U2@proxy.corp.example:3128/", "SK-CLEAR-U2"),
    ("userinfo_amqp", "amqp://rabbit:SK-CLEAR-U3@mq.internal:5672/%2f", "SK-CLEAR-U3"),
    ("github_pat", f"remote rejected for {_GITHUB_PAT}", _GITHUB_PAT),
    ("slack_bot_token", f"webhook auth {_SLACK_BOT}", _SLACK_BOT),
    ("aws_access_key_id", f"principal {_AWS_KEY_ID} is not authorized", _AWS_KEY_ID),
    (
        "azure_account_key",
        "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=SK-CLEAR-U4;",
        "SK-CLEAR-U4",
    ),
)


@pytest.mark.parametrize(
    ("text", "cleartext"),
    [(text, cleartext) for _, text, cleartext in _UNNAMED_CREDENTIALS],
    ids=[case_id for case_id, _, _ in _UNNAMED_CREDENTIALS],
)
def test_credentials_that_no_rule_named_are_redacted_on_both_paths(
    text: str, cleartext: str
) -> None:
    """R-013. These are value patterns, so unlike R-012 they close symmetrically."""
    assert cleartext not in redact({"detail": text})["detail"]
    assert cleartext not in redact_text(text)


def test_the_userinfo_rule_keeps_the_parts_that_make_a_failure_diagnosable() -> None:
    """Same trade the presigned-URL rule makes: redact the credential, keep the
    address. Which principal failed to authenticate, against which host and
    port, is the whole diagnostic content of a connection error."""
    out = redact({"detail": "postgres://appuser:SK-CLEAR-U5@db.internal:5432/prod"})["detail"]

    assert out == "postgres://appuser:<redacted>@db.internal:5432/prod"


def test_the_userinfo_rule_does_not_fire_without_an_at_sign() -> None:
    """The narrowing R-013 warns about. A rule that keyed on the colon alone
    would eat the port here; this one is anchored on `@` and cannot."""
    for endpoint in (
        "https://token-service.internal:8443/healthz",
        "postgres://db.internal:5432/prod",
        "cr.eu-north1.nebius.cloud/my-secrets-app:v1.4.2",
    ):
        assert redact({"endpoint": endpoint})["endpoint"] == endpoint


def test_provider_prefixes_do_not_fire_inside_a_base64_run() -> None:
    """What the leading \\b buys. `_` is a word character, so inside a base64url
    blob there is no boundary for the prefix to sit on."""
    blob = "Zm9vYmFy" + _GITHUB_PAT + "YmF6cXV4"
    assert redact({"ca_data": blob})["ca_data"] == blob


# ---------------------------------------------------------------------------
# criterion 2 — nothing that was recognised before stopped being recognised
# ---------------------------------------------------------------------------

# Every entry here is redacted by ``redact_text`` on main. R-015 records an
# attempt that rewrote this rule for cost and quietly stopped recognising six
# of them — PGPASSWORD, dbpassword, authtoken, apitoken, rootpassword,
# vaulttoken — because it matched the keyword as a whole name segment instead
# of as a substring. This corpus exists so that cannot happen silently again.
_STILL_RECOGNISED: tuple[str, ...] = (
    "env: PGPASSWORD=SK-CLEAR-N01",
    "dbpassword=SK-CLEAR-N02",
    "authtoken=SK-CLEAR-N03",
    "apitoken=SK-CLEAR-N04",
    "rootpassword=SK-CLEAR-N05",
    "vaulttoken=SK-CLEAR-N06",
    "api_key=SK-CLEAR-N07",
    "api-key=SK-CLEAR-N08",
    "apikey=SK-CLEAR-N09",
    "private_key=SK-CLEAR-N10",
    "private-key=SK-CLEAR-N11",
    "privatekey=SK-CLEAR-N12",
    "passwd=SK-CLEAR-N13",
    "authorization=SK-CLEAR-N14",
    "secret_key: SK-CLEAR-N15",
    "secretKey=SK-CLEAR-N16",
    "SECRET=SK-CLEAR-N17",
    "credential=SK-CLEAR-N18",
    "credentials=SK-CLEAR-N19",
    "access_token=SK-CLEAR-N20",
    "refresh_token=SK-CLEAR-N21",
    "bearer_token=SK-CLEAR-N22",
    "iam_token=SK-CLEAR-N23",
    "client_secret=SK-CLEAR-N24",
    "aws_secret_access_key=SK-CLEAR-N25",
    "x-api-key: SK-CLEAR-N26",
    "app.secret=SK-CLEAR-N27",
    'password="SK-CLEAR-N28"',
    "password='SK-CLEAR-N29'",
    "token = SK-CLEAR-N30",
    "token:\nSK-CLEAR-N31",
    "failed: db_password=SK-CLEAR-N32, retrying",
    "https://h/p?access_token=SK-CLEAR-N33&x=1",
    "MySecretThing=SK-CLEAR-N34",
    "secret=SK-CLEAR-N35;next=1",
    "{secret=SK-CLEAR-N36}",
    "user_password_2=SK-CLEAR-N37",
    '{secret_key: SK-CLEAR-N38, "a": 1}',
    "PASSWORD=SK-CLEAR-N39",
    "Secret_Key=SK-CLEAR-N40",
    "gcp_service_account_credential=SK-CLEAR-N41",
    "registry_password=SK-CLEAR-N42",
    "ssh_private_key=SK-CLEAR-N43",
    "docker_auth_token=SK-CLEAR-N44",
)


@pytest.mark.parametrize("text", _STILL_RECOGNISED, ids=lambda t: t.split("=")[0][:28])
def test_no_credential_name_stopped_being_recognised(text: str) -> None:
    cleartext = re.search(r"SK-CLEAR-N\d+", text)
    assert cleartext is not None
    assert cleartext.group() not in redact_text(text)


def test_the_denylist_now_reaches_the_error_path_too() -> None:
    """Widening, not narrowing. ``kubeconfig`` and ``user_data`` are on the
    exact denylist but contain none of the assignment keywords, so an
    ``kubeconfig=<blob>`` in an exception text used to survive."""
    assert "SK-CLEAR-W1" not in redact_text("kubeconfig=SK-CLEAR-W1")
    assert "SK-CLEAR-W2" not in redact_text("cloud_init_user_data=SK-CLEAR-W2")


def test_the_benign_list_now_reaches_the_error_path_too() -> None:
    """Narrowing, deliberately, and the one place this change recognises less.

    R-019 already decided that "<redacted>" on a usage counter or an expiry
    timestamp reads as data the account does not have. Without this the quoted
    spelling R-012 adds would newly mangle ``{"tokens_used": 4096}`` in an
    error message, which is a false positive R-019 spent a round removing from
    the mapping path.
    """
    assert redact_text('{"tokens_used": 4096}') == '{"tokens_used": 4096}'
    assert redact_text("token_expires_at: 2026-08-10T12:00:00Z") == (
        "token_expires_at: 2026-08-10T12:00:00Z"
    )
    # and the exact denylist still outranks it, on this path as on the other
    assert redact_text("access_token=SK-CLEAR-B1") != "access_token=SK-CLEAR-B1"


# ---------------------------------------------------------------------------
# criterion 3 — no new false positives
# ---------------------------------------------------------------------------

# Real Nebius, Kubernetes and registry shapes. Each must come out of ``redact``
# byte-identical. The six that ``redact_text`` mangles are listed separately
# below rather than omitted, because that mangling is pre-existing behaviour of
# the assignment rule and pinning it is what stops it being called a new bug.
_BENIGN_STRINGS: tuple[str, ...] = (
    "https://mk8s-cluster-e00abc.eu-north1.nebius.cloud:443",
    "token-service.internal:8443/healthz",
    "https://token-service.internal:8443/healthz",
    "10.0.0.14:6443",
    "kube-apiserver.default.svc.cluster.local:443",
    _HOST_WITH_SENSITIVE_NAME,
    "credentials-broker.svc:9000",
    "cr.eu-north1.nebius.cloud/my-secrets-app:v1.4.2",
    "cr.eu-north1.nebius.cloud/tokenizer:2.1.0-rc.3",
    "registry.k8s.io/kube-proxy:v1.30.2",
    "nvcr.io/nvidia/cuda:12.4.1-cudnn-runtime-ubuntu22.04",
    (
        "cr.eu-north1.nebius.cloud/password-reset@sha256:"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ),
    "2026-08-08T12:34:56Z",
    "2026-08-08T12:34:56.789012Z",
    "created_at 2026-08-08T12:34:56+03:00",
    "computeinstance-e00abcdef123456",
    "project-e00xyz9876543210",
    "vpcsubnet-e00aaaabbbbcccc1",
    "mk8scluster-e00ffff0000eeee2",
    "iamserviceaccount-e00deadbeef0001",
    "v1.30.2",
    "0.4.17",
    "nebius-mcp 0.2.0",
    "python 3.11.9",
    "metadata.name contains 'secret'",
    'labels."app.kubernetes.io/name"="token-service"',
    "status.phase = RUNNING",
    "spec.resources.platform = gpu-h100-sxm",
    "https://storage.eu-north1.nebius.cloud/bucket/object?versionId=3&prefix=logs%2F",
    "https://api.eu-north1.nebius.cloud/v1/instances?page_size=100",
    "https://docs.nebius.com/compute/instances#secret-management",
    "https://github.com/nebius/nebius-mcp/blob/main/SECURITY.md",
    "https://user@github.com/nebius/nebius-mcp.git",
    "git@github.com:nebius/nebius-mcp.git",
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJrVENDQVRlZ0F3SUJBZ0lRCg==",
    "ZXhhbXBsZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS1ibG9iLXdpdGgtbm8tc2VjcmV0cw==",
    "Rotate the secret before the credential audit; the password policy is annual.",
    "The token bucket refills every 60 seconds.",
    "This instance holds no credentials of any kind.",
    "See the secret management runbook for details.",
    "Tokenization is handled by the inference server.",
    "secret-rotation-runbook",
    "my-secrets-app",
    "vault-token-refresher",
    "password-policy-v2",
    "8443",
    "0.0.0.0/0",
    "eu-north1-a",
    "gpu-h100-sxm",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC",
    "PENDING",
    "RUNNING -> STOPPED",
    "1 of 3 nodes ready",
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "arn:aws:s3:::bucket/key",
    "user@example.com",
    "mailto:ops@nebius.example",
    "//comment: not a url",
    "AKIA" + "EXAMPLE",
    "ghp_" + "short",
    "xoxb-" + "1234",
    '{"tokens_used": 4096}',
    '{"token_expires_at": "2026-08-10T12:00:00Z"}',
    '{"max_tokens": 2048}',
    '{"secret_version_count": 3}',
    '{"credentials_expire_at": "2026-08-10T00:00:00Z"}',
)

# The assignment rule cannot tell these colons from the colon in
# `secret_key: value`, so `redact_text` mangles them. That is true on main and
# unchanged here, and it is exactly why the rule is not moved onto the success
# path where every endpoint and image reference would go through it.
_MANGLED_BY_THE_TEXT_PATH_ONLY: frozenset[str] = frozenset(
    {
        "token-service.internal:8443/healthz",
        "https://token-service.internal:8443/healthz",
        _HOST_WITH_SENSITIVE_NAME,
        "credentials-broker.svc:9000",
        "cr.eu-north1.nebius.cloud/my-secrets-app:v1.4.2",
        "cr.eu-north1.nebius.cloud/tokenizer:2.1.0-rc.3",
    }
)


@pytest.mark.parametrize("value", _BENIGN_STRINGS, ids=lambda s: s[:40])
def test_benign_nebius_shapes_survive_redact_unchanged(value: str) -> None:
    assert redact({"field": value})["field"] == value


@pytest.mark.parametrize(
    "value",
    [s for s in _BENIGN_STRINGS if s not in _MANGLED_BY_THE_TEXT_PATH_ONLY],
    ids=lambda s: s[:40],
)
def test_benign_nebius_shapes_survive_redact_text_unchanged(value: str) -> None:
    assert redact_text(value) == value


@pytest.mark.parametrize("value", sorted(_MANGLED_BY_THE_TEXT_PATH_ONLY))
def test_the_text_path_false_positives_are_pinned_not_forgotten(value: str) -> None:
    """If one of these starts surviving, the assignment rule got narrower and
    the corpus above should absorb it. If a *new* string joins them, the rule
    got wider. Either way this list should be edited deliberately."""
    assert redact_text(value) != value
    assert redact({"field": value})["field"] == value


# ---------------------------------------------------------------------------
# criterion 5 — idempotency
# ---------------------------------------------------------------------------

_ALL_CORPUS_STRINGS: tuple[str, ...] = (
    _BENIGN_STRINGS
    + _STILL_RECOGNISED
    + tuple(text for _, text, _ in _QUOTED_ASSIGNMENTS)
    + tuple(text for _, text, _ in _UNNAMED_CREDENTIALS)
)


@pytest.mark.parametrize("value", _ALL_CORPUS_STRINGS, ids=lambda s: s[:40])
def test_redaction_is_idempotent_over_both_corpora(value: str) -> None:
    once_mapping = redact({"f": value})["f"]
    assert redact({"f": once_mapping})["f"] == once_mapping

    once_text = redact_text(value)
    assert redact_text(once_text) == once_text


def test_redaction_is_idempotent_over_generated_strings() -> None:
    """Fuzzed rather than enumerated, because the failures found while writing
    this were all interactions between two rules rather than bugs in one.

    The three that showed up and were fixed: dropping the quotes around a
    redacted value let the unquoted alternative match further on the next pass;
    running the assignment rule before the value patterns let a value pattern's
    replacement become an assignment; and the Azure rule's value class
    re-consumed its own marker.
    """
    alphabet = [
        *list("abzAZ019_.-:= \t\n\"'{}[](),;&/@?#%*<>|\\+~^$!"),
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "api_key",
        "authorization",
        "PGPASSWORD",
        "tokens_used",
        "kubeconfig",
        "://",
        "eyJ",
        "AKIA",
        "ghp_",
        "xoxb-",
        "AccountKey=",
        "X-Amz-Signature=",
    ]
    rnd = random.Random(20260808)
    unstable: list[str] = []
    for _ in range(4000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(1, 60)))
        once = redact_text(text)
        if redact_text(once) != once:
            unstable.append(text)
        mapped = redact({"f": text})["f"]
        assert redact({"f": mapped})["f"] == mapped, text

    # Not zero. The known exception is pinned below; anything much above the
    # rate measured when this landed (9 in 60,000) means a new interaction.
    assert len(unstable) < 20, unstable[:5]


def test_redaction_is_not_idempotent_when_a_url_user_is_a_keyword() -> None:
    """The counterexample the docstring's narrowed claim refers to.

    ``/`` stops the userinfo rule matching, so the assignment rule fires on
    ``password:`` and removes the ``/``; on the next pass the userinfo rule can
    match, and the assignment rule then reaches past the ``]``. It redacts
    strictly more each time, never less, which is why it is documented rather
    than fixed — closing it would mean either iterating to a fixed point on
    every error string or making one of the two rules recognise less.
    """
    once = redact_text("://password:/]@")
    twice = redact_text(once)

    assert once == "://password:<redacted>]@"
    assert twice == "://password:<redacted>"


def test_a_second_pass_never_reveals_what_the_first_removed() -> None:
    """The property that holds universally where idempotency does not, and the
    only one of the two that is security-relevant."""
    rnd = random.Random(4242)
    alphabet = [*list("az09_.-:=@/ '\"[]{},;&<>"), "secret", "password", "://", "AccountKey="]
    for _ in range(4000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(1, 60)))
        once = redact_text(text)
        twice = redact_text(once)
        windows = {text[i : i + 6] for i in range(max(len(text) - 5, 0))}
        assert {w for w in windows if w in twice} <= {w for w in windows if w in once}, text


# ---------------------------------------------------------------------------
# the refactor itself — the run scanner must decide exactly what the old
# single regex decided
# ---------------------------------------------------------------------------


def test_the_run_scanner_matches_the_regex_it_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    """R-015's second attempt replaced this rule with a hand-written scanner
    and silently changed which names it recognised. Nothing caught it.

    So compare against the shape of the regex that was there, built from the
    live keyword tuple so that adding a keyword does not make this test stale.
    The three deliberate departures — the quote skip, the exact-list lookup and
    keeping the value's quotes — are switched off for the comparison; each has
    its own test above.
    """
    from nebius_mcp import sanitize

    reference = re.compile(
        r"([A-Za-z0-9_.-]*(?:"
        + "|".join(re.escape(k) for k in sanitize._ASSIGNMENT_KEYWORDS)
        + r")[A-Za-z0-9_.-]*)"
        r"(\s*[:=]\s*)"
        r"(\"[^\"]*\"|'[^']*'|[^\s,;&)\}\]]+)",
        re.IGNORECASE,
    )
    monkeypatch.setattr(sanitize, "_closing_quote_width", lambda text, start, end: 0)
    monkeypatch.setattr(sanitize, "_redacted_like", lambda value: "<redacted>")
    monkeypatch.setattr(
        sanitize,
        "_name_carries_a_secret",
        lambda name: any(k in name.lower() for k in sanitize._ASSIGNMENT_KEYWORDS),
    )

    alphabet = [
        *list("abzAZ019_.-:= \t\n\"'{}[](),;&/@?#%"),
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "api_key",
        "api-key",
        "private_key",
        "authorization",
        "SECRET",
        "PGPASSWORD",
    ]
    rnd = random.Random(1234567)
    for _ in range(3000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(1, 60)))
        assert sanitize._redact_assignments(text) == reference.sub(r"\1\2<redacted>", text), text


def test_the_short_name_shortcut_cannot_skip_a_real_name() -> None:
    """The length guard is a constant-factor optimisation for separator-dense
    text. Hard-coding it too high would silently disable whole keywords, which
    the fidelity test above would catch — this states the invariant directly."""
    from nebius_mcp import sanitize

    shortest = min(
        min(len(name) for name in sanitize._NORMALIZED_SENSITIVE_KEYS),
        min(len(keyword) for keyword in sanitize._ASSIGNMENT_KEYWORDS),
    )
    assert shortest >= sanitize._SHORTEST_SECRET_NAME


# ---------------------------------------------------------------------------
# criterion 1 — cost
# ---------------------------------------------------------------------------

# Shapes chosen because each one broke a previous attempt or a rule written
# here: an unbroken base64url/hex run (attempt 1, 69.6 s on 64 KB), a run of
# name characters (the old assignment regex, 12.8 s on 4 KB of it through
# redact_text), separator-dense text with no terminators (attempt 2, 11.9 s on
# 128 KB), and text dense in `://` and `@` (the first draft of the userinfo
# rule here, 1.7 s on 64 KB).
_COST_SHAPES: dict[str, str] = {
    "base64url": "aGVsbG8td29ybGQtdGhpcy1pcy1ub3QtYS1zZWNyZXQ",
    "hex": "0123456789abcdef",
    "name_chars": "secret_token.pass-word0",
    "colon_dense": "a:",
    "equals_dense": "a=",
    "keyword_dense": "secret:",
    "prose": "The secret rotation runbook and the credential audit are annual. ",
    "json": '{"name": "vm-01", "secret_key": "x", "port": 8443}, ',
    "querystring": "https://s.example/o?X-Amz-Expires=900&a=1&b=2 ",
    "slashes_and_ats": "//a@b//c@d://e:f@g ",
    "quoted_names": '"secret_key": "v", ',
    # The three shapes that matter for the JWT rule, and the omission that let
    # R-021 sit in this tuple through two reviews: every unit above breaks the
    # `[A-Za-z0-9_-]` run somewhere, so none of them ever gave that rule a long
    # unbroken run with many `eyJ` start positions to rescan. The first is the
    # adversarial form; the second is what base64 of any repeated JSON body
    # actually looks like, which is the realistic trigger; the third pairs the
    # prefix with a run made of the class characters themselves.
    "jwt_prefix_dense": "eyJ",
    "jwt_b64_json": "eyJhIjoxfXsiYSI6MX0",
    "jwt_prefix_and_run": "eyJab_cd-",
}

# 64 KB is the size R-015's attempt 1 was measured at, so the numbers compare
# directly: it took 69.6 s there, attempt 2 took 11.9 s on twice that, and this
# module takes 1.4-5.9 ms on the machine this was written on. The bound is 50
# ms — roughly ten times the slowest measurement, which leaves room for a CI
# runner several times slower than a laptop while still failing either reverted
# attempt by four orders of magnitude. The 512 KB bound is the one that
# actually detects a quadratic rule: eight times the input for eight times the
# budget, where anything quadratic needs sixty-four.
_COST_BUDGET_64K_SECONDS = 0.050
_COST_BUDGET_512K_SECONDS = 0.400


def _fastest(fn: Any, text: str) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        fn(text)
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("unit", _COST_SHAPES.values(), ids=list(_COST_SHAPES))
def test_redaction_cost_stays_linear(unit: str) -> None:
    for fn in (lambda t: redact({"x": t}), redact_text):
        small = (unit * (64_000 // len(unit) + 1))[:64_000]
        large = (unit * (512_000 // len(unit) + 1))[:512_000]

        assert _fastest(fn, small) < _COST_BUDGET_64K_SECONDS
        assert _fastest(fn, large) < _COST_BUDGET_512K_SECONDS


@pytest.mark.parametrize(
    "field",
    ["api_key", "apiKey", "api-key", "API_KEY", "wandb_api_key", "openai_api_key", "apikey"],
)
def test_a_field_named_api_key_is_redacted(field: str) -> None:
    """R-020: none of the four original substrings contained "apikey".

    `api_key` normalizes to `apikey`, which is not a substring of `secret`,
    `token`, `password` or `credential` — so the single most common name for a
    credential in the entire industry was returned verbatim, in every spelling.

    Found while mapping the Token Factory API, whose fine-tuning request carries
    an integrations block with `WandbConfigRequest.api_key`. The gap was never
    Token Factory-specific: nothing had ever matched this name on either plane.
    """
    assert redact({field: "sk-REAL-CREDENTIAL"})[field] == "<redacted>"


def test_openai_usage_counters_survive() -> None:
    """The other half of the same discovery, in the opposite direction.

    Token Factory returns OpenAI-shaped usage blocks. Four of those fields were
    redacted by the `token` substring while the four classic counters passed,
    only because the classic four were already on the benign list. A redacted
    counter reads as a value the account does not have.
    """
    usage = {
        "prompt_tokens": 10,
        "completion_tokens": 20,
        "total_tokens": 30,
        "cached_tokens": 5,
        "reasoning_tokens": 7,
        "completion_tokens_details": {"reasoning_tokens": 7},
        "prompt_tokens_details": {"cached_tokens": 5},
    }

    assert redact(usage) == usage

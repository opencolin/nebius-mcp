"""Tests for the long-running-operation summary.

The summary is the one API-sourced payload that used to reach the model without
passing through the sanitizer — recorded as R-010. ``description`` is free text
the control plane chooses and can quote a resource name, and resource names are
attacker-writable by anyone with write access to the account.

Two halves are pinned here, and both matter. That the redaction happens at all,
and that it does not corrupt the identifiers a caller needs in order to poll the
operation afterwards. R-015 is the argument for the second: the two previous
attempts to widen redaction in this project were both reverted for damage they
did to values nobody thought to check.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from nebius_mcp.operation import _summarize, maybe_wait

# Built at runtime rather than written as literals, following the same reasoning
# as ``tests/unit/test_sanitize.py``: a committed string that looks like a
# private key or a JWT trips secret scanners on every future commit that touches
# this file, and allowlisting the file would stop the scanner catching a real
# credential pasted here later. These have to *look* like credentials — that is
# the whole point of the test — so they are assembled instead of pasted.


def _pem(kind: str, body: str) -> str:
    begin = "-" * 5 + "BEGIN " + kind + " PRIVATE KEY" + "-" * 5
    end = "-" * 5 + "END " + kind + " PRIVATE KEY" + "-" * 5
    return begin + "\n" + body + "\n" + end


def _jwt() -> str:
    """A structurally valid JWT whose payload says it is not one."""
    import base64

    def seg(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    return ".".join(
        [seg('{"alg":"HS256"}'), seg('{"sub":"not-a-real-token"}'), seg("test-signature")]
    )


def _op(**overrides: Any) -> MagicMock:
    async def _wait(**_: Any) -> None:
        return None

    op = MagicMock()
    op.wait = _wait
    op.id = "operation-e00abcdef123456"
    op.resource_id = "computeinstance-e00abcdef123456"
    op.done = True
    op.successful = True
    op.status = "OK"
    op.description = "delete instance"
    for key, value in overrides.items():
        setattr(op, key, value)
    return op


# Each entry is (label, description as the API returned it, the substring that
# must not survive). Every one is a shape the sanitizer already knows how to
# recognise — the defect was never that these were unrecognisable, it was that
# nothing ran the rules over this field.
_LEAKY_DESCRIPTIONS: list[tuple[str, str, str]] = [
    (
        "jwt",
        "failed to reach instance: auth header was " + _jwt(),
        _jwt().split(".")[1],
    ),
    (
        "nebius_token",
        "callback rejected the token ne1abcdefghijklmnopqrstuvwxyz0123456789",
        "ne1abcdefghijklmnopqrstuvwxyz0123456789",
    ),
    (
        "pem",
        "instance metadata rejected: " + _pem("RSA", "Tk9UQVJFQUxLRVlteXN0ZXJ5Ym94"),
        "Tk9UQVJFQUxLRVlteXN0ZXJ5Ym94",
    ),
    (
        "presigned_url",
        "source image fetch failed: https://storage.eu-north1.nebius.cloud/b/o"
        "?X-Amz-Signature=deadbeefcafe1234",
        "deadbeefcafe1234",
    ),
]


@pytest.mark.parametrize(
    ("description", "cleartext"),
    [(d, c) for _, d, c in _LEAKY_DESCRIPTIONS],
    ids=[label for label, _, _ in _LEAKY_DESCRIPTIONS],
)
def test_operation_description_is_redacted(description: str, cleartext: str) -> None:
    """R-010: the summary reached the model with neither half of the sanitizer run."""
    summary = _summarize(_op(description=description))

    assert cleartext not in summary["description"]
    assert "<redacted>" in summary["description"]


def test_identifiers_survive_redaction() -> None:
    """The false-positive half.

    A redacted ``operation_id`` or ``resource_id`` is not a safe failure: the
    model needs both to poll the operation or to act on what was created, and a
    ``<redacted>`` cursor fails silently rather than loudly. This is the same
    hazard that keeps ``next_page_token`` outside ``redact`` altogether.
    """
    summary = _summarize(_op())

    assert summary["operation_id"] == "operation-e00abcdef123456"
    assert summary["resource_id"] == "computeinstance-e00abcdef123456"
    assert summary["done"] is True
    assert summary["successful"] is True
    assert summary["status"] == "OK"
    assert summary["description"] == "delete instance"


@pytest.mark.parametrize(
    "resource_id",
    [
        "computeinstance-e00abcdef123456",
        "computedisk-e00bbb444555666",
        "mk8scluster-e00aaa111222333",
        "vpcsubnet-e00ccc777888999",
        "project-e00ddd000111222",
        "tenant-e00eee333444555",
        "nvlinstancegroup-e00fff666777888",
    ],
)
def test_resource_ids_of_every_shape_survive(resource_id: str) -> None:
    """Widening redaction is how this project has broken things twice (R-015).

    Every ID prefix the catalog can produce goes through, so a value pattern
    that starts matching identifiers fails here rather than in someone's
    session.
    """
    assert _summarize(_op(resource_id=resource_id))["resource_id"] == resource_id


@pytest.mark.asyncio
async def test_maybe_wait_redacts_on_both_branches() -> None:
    """``wait=False`` returns the same summary without awaiting, so it needs the
    same treatment — the fire-and-forget path is not a lesser path."""
    secret = _jwt()

    waited = await maybe_wait(_op(description=secret), wait=True, timeout_seconds=1)
    unwaited = await maybe_wait(_op(description=secret), wait=False, timeout_seconds=1)

    for summary in (waited, unwaited):
        assert secret.split(".")[1] not in summary["description"]
        assert summary["description"] == "<redacted>"


def test_an_assignment_in_a_description_still_survives() -> None:
    """Pins R-012, which this change does not close, so nobody assumes it did.

    ``redact`` applies ``_SENSITIVE_VALUE_PATTERNS`` to a string and nothing
    else; the ``name=value`` rule lives only in ``redact_text``, on the error
    path. So routing the summary through ``redact`` closes the shapes that rule
    set knows — JWTs, PEM blocks, Nebius tokens, presigned-URL parameters — and
    leaves an assignment written into an operation description untouched.

    This test exists to fail loudly if someone widens ``redact`` to cover
    assignments, so that they find R-015 and read what happened the last two
    times before assuming it is a small change.
    """
    leaked = "provisioning failed at cloud-init line 4: db_password=hunter2correcthorse"

    assert _summarize(_op(description=leaked))["description"] == leaked


def test_a_missing_description_does_not_break_the_summary() -> None:
    """``getattr(op, "description", None)`` can yield None, and ``redact``
    has to pass a non-string through untouched rather than raising."""
    summary = _summarize(_op(description=None))

    assert summary["description"] is None
    assert summary["resource_id"] == "computeinstance-e00abcdef123456"

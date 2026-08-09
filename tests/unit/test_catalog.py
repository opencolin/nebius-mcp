"""Tests for the SDK resource catalog.

These guard the runtime derivation of request classes. If an SDK upgrade
renames or drops a service, these fail loudly instead of the generic tools
raising ToolError at call time.
"""

from __future__ import annotations

import logging
import warnings

import pytest

from nebius_mcp import catalog

# Imported for the contract test only: what the catalog advertises has to match
# the request shapes this module actually builds.
from nebius_mcp.tools import generic

_PROBE = "contract-probe"

# Restated here, not imported from catalog, on purpose: the contract test must
# fail if catalog's idea of the generic request shape drifts from the tools'.
# Mirrors nebius_resource_get / _delete / _action / _get_by_name / _list.
_ID_SHAPED = frozenset({"get", "delete", *generic._ACTIONS})


def _generic_kwargs(verb: str, request_cls: type) -> dict[str, object]:
    fields = frozenset(request_cls._public_fields_by_python_name())  # type: ignore[attr-defined]
    if verb in _ID_SHAPED:
        return {"id": _PROBE}
    if verb == "get_by_name":
        return {"parent_id": _PROBE, "name": _PROBE}
    if verb == "list":
        scope = "parent_id" if "parent_id" in fields else "resource_id"
        return {scope: _PROBE} if scope in fields else {}
    return {}


_ALL_PAIRS = [
    (spec.key, verb) for spec in catalog.RESOURCES for verb in sorted(catalog.verbs(spec.key))
]


def test_every_resource_resolves_a_client() -> None:
    for spec in catalog.RESOURCES:
        assert isinstance(catalog.client_class(spec.key), type), spec.key


def test_every_resource_exposes_at_least_one_verb() -> None:
    for spec in catalog.RESOURCES:
        assert catalog.verbs(spec.key), f"{spec.key} resolved no verbs"


def test_keys_are_unique() -> None:
    keys = [spec.key for spec in catalog.RESOURCES]
    assert len(keys) == len(set(keys))


def test_every_key_is_domain_qualified() -> None:
    for spec in catalog.RESOURCES:
        assert "." in spec.key, spec.key


@pytest.mark.parametrize(
    ("key", "verb", "expected"),
    [
        ("compute.instance", "list", "ListInstancesRequest"),
        ("compute.instance", "get", "GetInstanceRequest"),
        ("storage.bucket", "list", "ListBucketsRequest"),
        ("mysterybox.secret", "get", "GetSecretRequest"),
        # These three resolve only via the alias fallback: get_type_hints raises
        # NameError on an unrelated broken alias in iam.v1 / vpc.v1.
        ("iam.project", "get", "GetProjectRequest"),
        ("iam.project", "get_by_name", "GetProjectByNameRequest"),
        ("vpc.route_table", "get", "GetRouteTableRequest"),
    ],
)
def test_request_class_resolution(key: str, verb: str, expected: str) -> None:
    resolved = catalog.request_class(key, verb)
    assert resolved is not None, f"{key}.{verb} did not resolve"
    assert resolved.__name__ == expected


def test_unsupported_verb_returns_none() -> None:
    # PlatformService is read-only; it has no delete RPC.
    assert catalog.request_class("compute.platform", "delete") is None
    assert not catalog.supports("compute.platform", "delete")


def test_describe_reports_parent_semantics() -> None:
    described = catalog.describe(catalog.BY_KEY["mk8s.node_group"])
    assert described["resource_type"] == "mk8s.node_group"
    # Node groups are parented by a cluster, not a project — the single most
    # common Nebius API mistake, so it must be surfaced.
    assert "CLUSTER" in str(described["parent_id_means"])
    assert "list" in described["operations"]  # type: ignore[operator]


def test_alias_parser_rejects_non_alias_strings() -> None:
    assert catalog._resolve_alias("NotAnAlias") is None
    assert catalog._resolve_alias("_NebiusType_nebius_does_not_exist_Foo_deadbeef") is None


def test_every_list_capable_resource_resolves_its_collection_field() -> None:
    """A list response whose collection is not called `items` must still be read.

    Assuming `items` made managed PostgreSQL and OperationService return an
    empty list — indistinguishable from an account that genuinely has none,
    which is a wrong answer that looks like a correct one.
    """
    unresolved = [
        spec.key
        for spec in catalog.RESOURCES
        if catalog.supports(spec.key, "list") and catalog.list_items_field(spec.key) is None
    ]
    assert not unresolved, f"no collection field resolved for: {unresolved}"


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("compute.instance", "items"),
        ("msp.postgresql_cluster", "clusters"),
        ("msp.postgresql_backup", "backups"),
        ("common.operation", "operations"),
    ],
)
def test_known_collection_field_names(key: str, expected: str) -> None:
    assert catalog.list_items_field(key) == expected


@pytest.mark.parametrize(("key", "verb"), _ALL_PAIRS, ids=[f"{k}.{v}" for k, v in _ALL_PAIRS])
def test_every_advertised_verb_can_have_its_request_built(key: str, verb: str) -> None:
    """Advertising an operation the generic tools cannot even construct is a lie.

    Eight pairs failed this before the shape probe existed: FederationService
    wants ``federation_id``, PostgreSQL backups want ``backup_id`` plus
    ``cluster_id``, the audit export ``start`` wants a whole spec, and the three
    access-key mutations declare a field called ``id`` that is a ``KeyIdentity``
    message rather than a string — so even a field-name check passes and
    construction still raises.
    """
    request_cls = catalog.request_class(key, verb)
    assert request_cls is not None, f"{key}.{verb} advertised but resolved no request class"
    request_cls(**_generic_kwargs(verb, request_cls))


def test_withheld_verbs_exist_in_the_sdk_and_really_cannot_be_built() -> None:
    """Whatever ``verbs()`` drops must be droppable for a reason we can show.

    Derived, never listed: the SDK is the authority on which pairs these are.
    """
    for spec in catalog.RESOURCES:
        withheld = catalog.sdk_verbs(spec.key) - catalog.verbs(spec.key)
        for verb in withheld:
            request_cls = catalog.request_class(spec.key, verb)
            assert request_cls is not None, f"{spec.key}.{verb} withheld but absent from the SDK"
            reason = catalog.unreachable_reason(spec.key, verb)
            assert reason, f"{spec.key}.{verb} withheld with no reason"
            with pytest.raises(Exception):  # noqa: B017 - the SDK's own error is the reason
                request_cls(**_generic_kwargs(verb, request_cls))


def test_verbs_is_a_subset_of_the_raw_sdk_surface() -> None:
    for spec in catalog.RESOURCES:
        assert catalog.verbs(spec.key) <= catalog.sdk_verbs(spec.key), spec.key


def test_describe_advertises_only_constructible_operations() -> None:
    for spec in catalog.RESOURCES:
        described = catalog.describe(spec)
        assert described["operations"] == sorted(catalog.verbs(spec.key)), spec.key
        withheld = catalog.sdk_verbs(spec.key) - catalog.verbs(spec.key)
        assert not withheld & set(described["operations"]), spec.key  # type: ignore[arg-type]


def test_shape_probe_has_no_observable_side_effects() -> None:
    """The probe builds requests purely to see whether they build.

    It must not reach the network (it cannot — construction is in-memory field
    assignment) and must not log or warn either: it runs behind an ``@cache`` on
    a path that feeds ``nebius_list_resource_types``. Setting the deprecated
    compute ``filter`` fields, for instance, makes the SDK log a warning, which
    is why the probe leaves the optional list passthroughs alone.
    """
    catalog.unreachable_reason.cache_clear()
    catalog.verbs.cache_clear()
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture()
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            for spec in catalog.RESOURCES:
                catalog.verbs(spec.key)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)

    assert not records, [r.getMessage() for r in records]
    assert not caught, [str(c.message) for c in caught]

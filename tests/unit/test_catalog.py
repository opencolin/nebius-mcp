"""Tests for the SDK resource catalog.

These guard the runtime derivation of request classes. If an SDK upgrade
renames or drops a service, these fail loudly instead of the generic tools
raising ToolError at call time.
"""

from __future__ import annotations

import pytest

from nebius_mcp import catalog


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

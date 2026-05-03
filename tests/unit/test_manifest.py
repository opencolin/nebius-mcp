"""Tests for the tool-manifest hash (rug-pull / tool-poisoning detection)."""

from __future__ import annotations

import pytest

from nebius_mcp.manifest import build_manifest, hash_manifest, manifest_summary
from nebius_mcp.server import _build_app


@pytest.mark.asyncio
async def test_manifest_includes_all_registered_tools() -> None:
    app = _build_app()
    manifest = await build_manifest(app)
    names = [t["name"] for t in manifest["tools"]]
    assert manifest["tool_count"] == len(names)
    # spot-check a couple of categories so accidental tool removal fails CI
    assert "ping" in names
    assert "check_environment" in names
    assert "iam_whoami" in names
    assert "compute_list_instances" in names
    assert "k8s_list_clusters" in names
    assert "ai_list_endpoints" in names
    assert "vpc_list_networks" in names
    assert "registry_list" in names
    assert "secrets_list" in names
    assert "get_manifest" in names
    # Destructive coverage spot-checks
    assert "compute_delete_instance" in names
    assert "compute_create_instance" in names
    assert "k8s_delete_cluster" in names
    assert "ai_delete_endpoint" in names
    assert "vpc_delete_network" in names
    assert "registry_delete" in names


@pytest.mark.asyncio
async def test_manifest_hash_is_stable_across_rebuilds() -> None:
    h1 = hash_manifest(await build_manifest(_build_app()))
    h2 = hash_manifest(await build_manifest(_build_app()))
    assert h1 == h2


@pytest.mark.asyncio
async def test_manifest_summary_includes_hash() -> None:
    summary = await manifest_summary(_build_app())
    assert "sha256" in summary
    assert len(summary["sha256"]) == 64  # SHA-256 hex
    assert "tools" in summary
    assert summary["tool_count"] >= 50


@pytest.mark.asyncio
async def test_manifest_changes_when_description_changes() -> None:
    """Mutating any tool description must change the hash (defense vs rug-pull)."""
    app = _build_app()
    manifest = await build_manifest(app)
    h1 = hash_manifest(manifest)

    # Mutate one description in-memory and recompute
    mutated = {
        "tool_count": manifest["tool_count"],
        "tools": [
            {**t, "description": "TAMPERED"} if t["name"] == "ping" else t
            for t in manifest["tools"]
        ],
    }
    h2 = hash_manifest(mutated)
    assert h1 != h2

"""Tool-manifest hashing.

The collection of tool name + description + annotations + input schema is
itself an attack surface (Invariant Labs "tool poisoning", Trail of Bits
"line jumping"). Mutating these strings is a known rug-pull vector — even
without changing tool *behavior*, a hostile description can re-direct the
model's tool-selection.

This module computes a stable SHA-256 over the entire registered tool
surface so callers (and CI) can detect any change between releases.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastmcp import FastMCP


def _tool_record(tool: Any) -> dict[str, Any]:
    """Canonicalize one tool's MCP representation for hashing.

    Excludes anything that can vary at runtime (timestamps, instance IDs).
    """
    mcp = tool.to_mcp_tool()
    annotations = None
    if mcp.annotations is not None:
        annotations = mcp.annotations.model_dump(exclude_none=True, mode="json")
    return {
        "name": mcp.name,
        "description": mcp.description,
        "annotations": annotations,
        "inputSchema": mcp.inputSchema,
    }


async def build_manifest(app: FastMCP) -> dict[str, Any]:
    """Build a deterministic manifest of all registered tools."""
    tools = await app.list_tools()
    records = sorted([_tool_record(t) for t in tools], key=lambda r: r["name"])
    return {
        "tool_count": len(records),
        "tools": records,
    }


def hash_manifest(manifest: dict[str, Any]) -> str:
    """SHA-256 over the canonicalized manifest. Stable across runs."""
    blob = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


async def manifest_summary(app: FastMCP) -> dict[str, Any]:
    """Manifest plus its hash. Returned to callers verbatim."""
    manifest = await build_manifest(app)
    return {"sha256": hash_manifest(manifest), **manifest}

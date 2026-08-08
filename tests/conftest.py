"""Global test isolation.

The unit suite must never read the developer's real Nebius configuration.
``resolve_credentials`` falls back to ``~/.nebius/config.yaml`` whenever a
tool is called without an explicit ``parent_id``, so on any machine that has
actually used the ``nebius`` CLI the "no parent configured" code paths would
silently resolve a real project ID and take the wrong branch.

CI passes without this only because the runner has no ``~/.nebius``. Pinning
the config path at a guaranteed-missing location makes the suite hermetic
everywhere.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_nebius_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "nebius_mcp.auth.DEFAULT_CONFIG_PATH",
        tmp_path / "nonexistent" / "config.yaml",
    )
    for var in ("NEBIUS_IAM_TOKEN", "NEBIUS_PROFILE", "NEBIUS_MCP_MODE"):
        monkeypatch.delenv(var, raising=False)

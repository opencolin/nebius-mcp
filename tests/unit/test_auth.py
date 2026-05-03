"""Tests for credential resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from nebius_mcp.auth import (
    AuthError,
    CredentialResolution,
    get_sdk,
    reset_sdk,
    resolve_credentials,
)


@pytest.fixture(autouse=True)
def _clean_sdk_singleton() -> None:
    reset_sdk()


def test_resolve_no_creds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    snap = resolve_credentials(config_path=tmp_path / "missing.yaml")
    assert snap.has_any is False
    assert snap.iam_token_env is False
    assert snap.config_file_exists is False
    assert snap.active_profile is None


def test_resolve_token_env_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    snap = resolve_credentials(config_path=tmp_path / "missing.yaml")
    assert snap.has_any is True
    assert snap.iam_token_env is True


def test_resolve_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: prod\n"
        "profiles:\n"
        "  prod:\n"
        "    endpoint: api.eu.nebius.cloud\n"
        "    parent-id: project-abc123\n"
        "    auth-type: federation\n",
        encoding="utf-8",
    )
    snap = resolve_credentials(config_path=cfg)
    assert snap.has_any is True
    assert snap.active_profile == "prod"
    assert snap.parent_id == "project-abc123"
    assert snap.endpoint == "api.eu.nebius.cloud"


def test_resolve_profile_env_overrides_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.setenv("NEBIUS_PROFILE", "staging")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: prod\n"
        "profiles:\n"
        "  prod: {parent-id: project-prod}\n"
        "  staging: {parent-id: project-staging}\n",
        encoding="utf-8",
    )
    snap = resolve_credentials(config_path=cfg)
    assert snap.active_profile == "staging"
    assert snap.parent_id == "project-staging"


def test_resolve_malformed_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("::: not: yaml :::", encoding="utf-8")
    snap = resolve_credentials(config_path=cfg)
    assert snap.error is not None
    assert "failed to parse" in snap.error


def test_get_sdk_raises_without_creds(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    monkeypatch.setattr("nebius_mcp.auth.DEFAULT_CONFIG_PATH", tmp_path / "missing.yaml")
    with pytest.raises(AuthError) as ei:
        get_sdk()
    assert "NEBIUS_IAM_TOKEN" in str(ei.value)


def test_credential_resolution_dataclass() -> None:
    snap = CredentialResolution(
        iam_token_env=True,
        profile_env=None,
        config_file_path=Path("/nope"),
        config_file_exists=False,
        active_profile=None,
        parent_id=None,
        endpoint=None,
        error=None,
    )
    assert snap.has_any is True

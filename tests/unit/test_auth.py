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
        "    auth-type: federation\n"
        "    federation-id: federation-abc\n",
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


def test_federation_profile_without_federation_id_is_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A profile can parse cleanly and still be unable to authenticate.

    The SDK refuses to build from this shape with
    ``ConfigError: Missing federation-id in the profile``. Reporting
    has_any=True here would tell someone their credentials are fine while
    every tool fails.
    """
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: prod\nprofiles:\n  prod:\n    auth-type: federation\n    parent-id: project-a\n",
        encoding="utf-8",
    )
    snap = resolve_credentials(config_path=cfg)
    assert snap.has_any is False
    assert snap.profile_problem is not None
    assert "federation-id" in snap.profile_problem


def test_service_account_profile_missing_keys_is_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: ci\nprofiles:\n  ci:\n    auth-type: service account\n"
        "    service-account-id: serviceaccount-a\n",
        encoding="utf-8",
    )
    snap = resolve_credentials(config_path=cfg)
    assert snap.has_any is False
    assert snap.profile_problem is not None
    assert "public-key-id" in snap.profile_problem


def test_env_token_wins_over_a_broken_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit token must still work even if the config file is unusable."""
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: prod\nprofiles:\n  prod:\n    auth-type: federation\n",
        encoding="utf-8",
    )
    snap = resolve_credentials(config_path=cfg)
    assert snap.has_any is True


def test_get_sdk_prefers_env_token_over_broken_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEBIUS_IAM_TOKEN is precedence rule 1 and must not be blocked by a bad profile."""
    monkeypatch.setenv("NEBIUS_IAM_TOKEN", "tok-fake")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: prod\nprofiles:\n  prod:\n    auth-type: federation\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("nebius_mcp.auth.DEFAULT_CONFIG_PATH", cfg)
    reset_sdk()
    # Must not raise AuthError about the profile. Constructing the real SDK is
    # offline, so this exercises the whole resolution path.
    sdk = get_sdk()
    assert sdk is not None
    reset_sdk()


def test_get_sdk_reports_broken_profile_when_no_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NEBIUS_IAM_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_PROFILE", raising=False)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "default: prod\nprofiles:\n  prod:\n    auth-type: federation\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("nebius_mcp.auth.DEFAULT_CONFIG_PATH", cfg)
    reset_sdk()
    with pytest.raises(AuthError) as excinfo:
        get_sdk()
    assert "federation-id" in str(excinfo.value)
    reset_sdk()

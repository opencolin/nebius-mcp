"""Credential resolution for the Nebius SDK.

Precedence (matches the upstream Python SDK / nebius CLI conventions):

1. ``NEBIUS_IAM_TOKEN``  - short-lived bearer token
2. ``NEBIUS_PROFILE``    - profile name in ``~/.nebius/config.yaml`` (with a
   service-account keyfile or token-file)
3. ``current-profile``   - whatever the config file's default points at

Resolution is deliberately non-fatal: the preflight ``check_environment`` tool
should be able to report partial state ("token env present, but no config
file") without raising. Tools that actually need to talk to Nebius go through
:func:`get_sdk`, which lazily instantiates a singleton and raises
:class:`AuthError` when nothing usable was found.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nebius.sdk import SDK

DEFAULT_CONFIG_PATH = Path("~/.nebius/config.yaml").expanduser()


class AuthError(RuntimeError):
    """Raised when no usable Nebius credentials are available."""


@dataclass(frozen=True)
class CredentialResolution:
    """Snapshot of which credential sources are present in this environment."""

    iam_token_env: bool
    profile_env: str | None
    config_file_path: Path
    config_file_exists: bool
    active_profile: str | None
    parent_id: str | None
    endpoint: str | None
    error: str | None  # populated when the config file exists but couldn't be parsed

    @property
    def has_any(self) -> bool:
        return self.iam_token_env or (self.config_file_exists and self.active_profile is not None)


def resolve_credentials(
    config_path: Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> CredentialResolution:
    """Inspect the environment without making any network calls.

    Used by both ``get_sdk`` (which fails fast) and the ``check_environment``
    tool (which reports the snapshot to the LLM).
    """
    env_view: Mapping[str, str] = os.environ if env is None else env
    cfg_path = config_path or DEFAULT_CONFIG_PATH

    iam_token_env = bool(env_view.get("NEBIUS_IAM_TOKEN"))
    profile_env = env_view.get("NEBIUS_PROFILE") or None
    cfg_exists = cfg_path.exists()

    active_profile: str | None = None
    parent_id: str | None = None
    endpoint: str | None = None
    error: str | None = None

    if cfg_exists:
        try:
            import yaml  # type: ignore[import-untyped]  # bundled via pyyaml (transitive of nebius)

            with cfg_path.open("r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            active_profile = profile_env or cfg.get("default") or cfg.get("current-profile")
            profiles = cfg.get("profiles") or {}
            if active_profile and active_profile in profiles:
                p = profiles[active_profile] or {}
                parent_id = p.get("parent-id") or None
                endpoint = p.get("endpoint") or cfg.get("endpoint") or None
        except Exception as exc:
            error = f"failed to parse {cfg_path}: {exc!s}"

    return CredentialResolution(
        iam_token_env=iam_token_env,
        profile_env=profile_env,
        config_file_path=cfg_path,
        config_file_exists=cfg_exists,
        active_profile=active_profile,
        parent_id=parent_id,
        endpoint=endpoint,
        error=error,
    )


_sdk_lock = threading.Lock()
_sdk_instance: SDK | None = None


def get_sdk() -> SDK:
    """Return a singleton, configured Nebius ``SDK``.

    Raises :class:`AuthError` if no credential source is present. The SDK is
    constructed with no explicit credentials, letting its built-in ``Config``
    apply the same precedence (env token > profile > default) we report from
    :func:`resolve_credentials`.
    """
    global _sdk_instance
    cached = _sdk_instance
    if cached is not None:
        return cached

    with _sdk_lock:
        if _sdk_instance is not None:
            return _sdk_instance

        snapshot = resolve_credentials()
        if not snapshot.has_any:
            raise AuthError(_no_credentials_message(snapshot))

        from nebius.sdk import SDK as _SDK  # heavy import, kept lazy

        _sdk_instance = _SDK()
        return _sdk_instance


def reset_sdk() -> None:
    """Drop the cached SDK. Intended for tests."""
    global _sdk_instance
    with _sdk_lock:
        _sdk_instance = None


def _no_credentials_message(snapshot: CredentialResolution) -> str:
    lines = [
        "No Nebius credentials found. Configure one of:",
        "  1. export NEBIUS_IAM_TOKEN=<short-lived bearer token>",
        f"  2. ensure {snapshot.config_file_path} exists with a valid profile",
        "     (run `nebius profile create` then `nebius iam login`)",
        "  3. set NEBIUS_PROFILE to point at a profile in that config file",
    ]
    if snapshot.error:
        lines.append(f"Note: config file present but could not be parsed: {snapshot.error}")
    return "\n".join(lines)

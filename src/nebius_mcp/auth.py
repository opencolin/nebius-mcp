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
    profile_problem: str | None = None
    """Set when the active profile exists but cannot produce credentials.

    A profile being *present* is not the same as it being *usable*: a
    ``federation`` profile with no ``federation-id``, or a service-account
    profile missing its key, parses fine and then fails on the first API call.
    Reporting only presence gives false confidence at exactly the moment
    someone is trying to work out why every tool errors.
    """

    @property
    def has_any(self) -> bool:
        if self.iam_token_env:
            return True
        return (
            self.config_file_exists
            and self.active_profile is not None
            and self.profile_problem is None
        )


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
    profile_problem: str | None = None

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
                profile_problem = _profile_problem(p)
            elif active_profile:
                profile_problem = f"profile {active_profile!r} is not defined in the config file"
            else:
                profile_problem = "no default profile is set in the config file"
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
        profile_problem=profile_problem,
    )


def _profile_problem(profile: Mapping[str, object]) -> str | None:
    """Report why a profile cannot produce credentials, or None if it looks usable.

    Mirrors the fields ``nebius.aio.cli_config.Config`` requires. Catching this
    here turns a first-tool-call ``ConfigError`` into an answer from
    ``check_environment``, which is where someone debugging will look.
    """
    auth_type = str(profile.get("auth-type") or "").strip().lower()

    if auth_type in {"federation", "federated"}:
        if not profile.get("federation-id"):
            return (
                "auth-type is 'federation' but the profile has no 'federation-id'. "
                "Run `nebius iam login` to rewrite the profile, or set NEBIUS_IAM_TOKEN."
            )
        return None

    # The CLI has written this key both ways over time; accept either spelling.
    if auth_type in {"service account", "service-account"}:
        missing = [
            key
            for key in ("service-account-id", "public-key-id", "private-key-file-path")
            if not profile.get(key)
        ]
        if missing:
            return f"auth-type is '{auth_type}' but the profile is missing: {', '.join(missing)}."
        return None

    # Any other auth-type (including absent) is left to the SDK. Only flag what
    # has been confirmed to fail, so this never blocks a working setup.
    return None


_sdk_lock = threading.Lock()
_sdk_instance: SDK | None = None


def get_sdk() -> SDK:
    """Return a singleton, configured Nebius ``SDK``.

    Raises :class:`AuthError` if no credential source is present or the active
    profile cannot produce credentials.

    The SDK must be built with an explicit ``config_reader``. A bare ``SDK()``
    does *not* read ``~/.nebius/config.yaml`` — it falls back to ``EnvBearer``
    and fails with ``NoTokenInEnvError`` unless ``NEBIUS_IAM_TOKEN`` is set.
    That silently breaks precedence rules 2 and 3 (``NEBIUS_PROFILE`` and the
    config file), which is the setup the ``nebius`` CLI produces and the one
    most users have.

    ``Config`` implements rules 2 and 3, but *not* rule 1 on its own: its
    constructor raises ``FileNotFoundError`` when the config file is missing,
    before any env bearer is consulted. So a token-only environment — the
    documented Docker and CI path — is handled separately below rather than
    routed through ``Config``. See R-017.
    """
    global _sdk_instance
    cached = _sdk_instance
    if cached is not None:
        return cached

    with _sdk_lock:
        if _sdk_instance is not None:
            return _sdk_instance

        snapshot = resolve_credentials()
        # An explicit token is precedence rule 1 and stands on its own, so a
        # broken profile must not block it. Otherwise report the *specific*
        # problem before the generic "nothing configured" message, which would
        # otherwise tell someone to create a profile they already have.
        if not snapshot.iam_token_env:
            if snapshot.profile_problem:
                raise AuthError(
                    f"Nebius profile {snapshot.active_profile!r} is not usable: "
                    f"{snapshot.profile_problem}"
                )
            if not snapshot.has_any:
                raise AuthError(_no_credentials_message(snapshot))

        from nebius.aio.cli_config import Config  # heavy import, kept lazy
        from nebius.sdk import SDK as _SDK

        def _env_token_sdk() -> SDK:
            """Build against ``NEBIUS_IAM_TOKEN`` alone, with no config file.

            A bare ``SDK()`` resolves ``EnvBearer`` from the environment, which
            is precedence rule 1 exactly. It is the *only* way to honour that
            rule: ``Config.__init__`` eagerly calls ``_get_profile()``, whose
            first statement raises ``FileNotFoundError`` when the config file is
            absent — before any env bearer is consulted. Routing a token-only
            setup through ``Config`` therefore failed with advice to set the
            variable the caller had already set, which is the whole of R-017.
            """
            return _SDK(federation_invitation_no_browser_open=True)

        # Rule 1 needs no config file. Check this before touching Config at all,
        # because Config cannot be constructed without one.
        if snapshot.iam_token_env and not snapshot.config_file_exists:
            _sdk_instance = _env_token_sdk()
            return _sdk_instance

        try:
            _sdk_instance = _SDK(
                config_reader=Config(
                    config_file=snapshot.config_file_path,
                    # parent_id is resolved by us, per tool; the SDK raising
                    # NoParentIdError at construction would break every tool
                    # on a profile that simply has no default project.
                    no_parent_id=True,
                ),
                # Never try to pop a browser open: this process is an MCP server
                # attached to a client's stdio, not an interactive terminal.
                federation_invitation_no_browser_open=True,
            )
        except Exception as exc:  # ConfigError and friends
            # A file that exists but cannot be read is still not a reason to
            # refuse a caller who supplied a token: rule 1 outranks rules 2
            # and 3, so a malformed or unreadable config must not be able to
            # veto it. Only report the config failure when the token is absent
            # and there is genuinely nothing left to try.
            if snapshot.iam_token_env:
                _sdk_instance = _env_token_sdk()
                return _sdk_instance
            raise AuthError(
                f"Could not build a Nebius client from {snapshot.config_file_path}: {exc}. "
                "Run `nebius iam login` to refresh the profile, or set NEBIUS_IAM_TOKEN."
            ) from exc
        return _sdk_instance


def reset_sdk() -> None:
    """Drop the cached SDK, and everything bound to it.

    ``client._clients`` memoises service stubs constructed against whatever
    ``get_sdk()`` returned. Dropping the SDK without dropping those leaves the
    next ``service()`` call returning a stub that holds the discarded channel,
    while ``get_sdk()`` builds a fresh SDK nobody uses.

    That is latent today — the stdio server builds once and never resets — and
    stops being latent the moment anything re-resolves credentials at runtime,
    which a refresh after the documented 12-hour token expiry would. Enforcing
    the invariant here means no future caller has to remember it.

    The import is local because ``client`` imports this module; at module scope
    it would be a cycle.
    """
    from .client import reset_clients

    global _sdk_instance
    with _sdk_lock:
        _sdk_instance = None
    reset_clients()


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

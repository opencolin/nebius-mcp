"""Cross-cutting ops tools.

These are not tied to any one Nebius service:

- ``ping``                - liveness check
- ``check_environment``   - preflight: SDK + credential resolution snapshot
"""

from __future__ import annotations

import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from .. import __version__ as nebius_mcp_version
from ..auth import resolve_credentials
from ..server import is_write_mode


class CredentialSummary(BaseModel):
    """What credential sources the server can see, without contacting Nebius."""

    iam_token_env_set: bool = Field(description="True if NEBIUS_IAM_TOKEN is set.")
    profile_env: str | None = Field(description="Value of NEBIUS_PROFILE, if set.")
    config_file_path: str
    config_file_exists: bool
    active_profile: str | None = Field(
        description="Profile name we'd resolve to (env override, then config default)."
    )
    parent_id: str | None = Field(
        description="parent-id from the active profile, if any. Many tools require this."
    )
    endpoint: str | None
    config_parse_error: str | None = Field(
        default=None,
        description="Set when the config file exists but could not be parsed.",
    )


class EnvironmentReport(BaseModel):
    """Preflight report for nebius-mcp."""

    nebius_mcp_version: str
    nebius_sdk_version: str
    python_version: str
    platform: str
    mode: Literal["read", "write"]
    has_credentials: bool = Field(
        description="True if at least one credential source resolved. False means tools "
        "that hit Nebius will raise AuthError."
    )
    credentials: CredentialSummary
    next_steps: list[str] = Field(
        default_factory=list,
        description="Human-readable hints for the LLM when the environment is incomplete.",
    )


def _sdk_version() -> str:
    try:
        return version("nebius")
    except PackageNotFoundError:
        return "unknown"


def _build_report() -> EnvironmentReport:
    snap = resolve_credentials()
    summary = CredentialSummary(
        iam_token_env_set=snap.iam_token_env,
        profile_env=snap.profile_env,
        config_file_path=str(snap.config_file_path),
        config_file_exists=snap.config_file_exists,
        active_profile=snap.active_profile,
        parent_id=snap.parent_id,
        endpoint=snap.endpoint,
        config_parse_error=snap.error,
    )

    next_steps: list[str] = []
    if not snap.has_any:
        next_steps.extend(
            [
                "Set NEBIUS_IAM_TOKEN to a short-lived bearer token, or",
                f"Create a profile in {snap.config_file_path} "
                "(`nebius profile create` then `nebius iam login`).",
            ]
        )
    elif snap.config_file_exists and snap.active_profile and not snap.parent_id:
        next_steps.append(
            "Active profile has no parent-id. Many resource lookups need a project/folder ID; "
            "set parent-id in the profile or pass it explicitly to tools that accept one."
        )
    if snap.error:
        next_steps.append(f"Fix the config file: {snap.error}")

    return EnvironmentReport(
        nebius_mcp_version=nebius_mcp_version,
        nebius_sdk_version=_sdk_version(),
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        mode="write" if is_write_mode() else "read",
        has_credentials=snap.has_any,
        credentials=summary,
        next_steps=next_steps,
    )


def register(app: FastMCP) -> None:
    @app.tool(
        name="ping",
        description="Returns 'pong'. Liveness check that nebius-mcp is reachable.",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    def ping() -> str:
        return "pong"

    @app.tool(
        name="check_environment",
        description=(
            "Preflight check for nebius-mcp. Reports the server version, the Nebius "
            "SDK version, the current operating mode (read or write), and which "
            "credential sources are visible. Does not make any Nebius API calls. "
            "Use this when a Nebius tool is failing in an unexpected way, before "
            "asking the user for credentials, or to confirm which project/profile "
            "is active. The 'next_steps' field tells you exactly what is missing."
        ),
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    def check_environment() -> EnvironmentReport:
        return _build_report()

    @app.tool(
        name="get_manifest",
        description=(
            "Return a SHA-256 hash and full listing of every tool this server "
            "exposes (name, description, annotations, input schema). Use this to "
            "detect whether the tool surface has been tampered with between "
            "sessions — pin the sha256 in your environment and compare. Read-only."
        ),
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    async def get_manifest() -> dict[str, Any]:
        from ..manifest import manifest_summary

        return await manifest_summary(app)

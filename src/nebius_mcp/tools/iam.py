"""IAM read tools.

v1: ``iam_whoami``           -> who is the active principal
v2: ``iam_list_projects``    -> projects under a tenant
v2: ``iam_get_project``      -> single project detail
"""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from ..auth import resolve_credentials
from ..client import service
from ..errors import safe
from ..pagination import clamp_page_size
from ..sanitize import safe_proto, wrap

READ_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def _profile_parent_id() -> str | None:
    return resolve_credentials().parent_id


def register(app: FastMCP) -> None:
    @app.tool(
        name="iam_whoami",
        description=(
            "Identify the principal nebius-mcp is acting as. Returns the active "
            "user profile or service-account profile (whichever the credentials "
            "resolve to). Use this to confirm authentication and to discover the "
            "tenant_id needed by other IAM tools."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def iam_whoami() -> dict[str, Any]:
        from nebius.api.nebius.iam.v1 import GetProfileRequest, ProfileServiceClient

        client = service(ProfileServiceClient)
        resp = await safe(client.get(GetProfileRequest()))
        return wrap(safe_proto(resp))

    @app.tool(
        name="iam_list_projects",
        description=(
            "List projects under a tenant. Pass parent_id as a tenant ID "
            "(e.g. 'tenant-...'). If omitted, falls back to parent-id from the "
            "active profile, which may be a project id rather than a tenant id "
            "— in that case the call will fail with NebiusAPIError; call "
            "iam_whoami first to discover the tenant."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def iam_list_projects(
        parent_id: Annotated[
            str | None,
            Field(description="Tenant ID. Omit to use active profile parent-id.", default=None),
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Items per page (capped to 200, default 50).", default=None, ge=1),
        ] = None,
        page_token: Annotated[
            str | None,
            Field(description="Opaque pagination token from a previous response.", default=None),
        ] = None,
        filter: Annotated[
            str | None,
            Field(description="Server-side filter expression.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.iam.v2 import ListProjectsRequest, ProjectServiceClient

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="parent_id not provided and not discoverable from profile.",
            )

        client = service(ProjectServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token
        if filter:
            kwargs["filter"] = filter

        resp = await safe(client.list(ListProjectsRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

    @app.tool(
        name="iam_get_project",
        description=(
            "Get a single Nebius project by ID. Returns metadata (name, tenant, "
            "labels) and spec/status fields."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def iam_get_project(
        id: Annotated[str, Field(description="Project ID, e.g. 'project-...'.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.iam.v2 import GetProjectRequest, ProjectServiceClient

        client = service(ProjectServiceClient)
        resp = await safe(client.get(GetProjectRequest(id=id)))
        return wrap(safe_proto(resp))

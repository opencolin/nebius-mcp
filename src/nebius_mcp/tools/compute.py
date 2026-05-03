"""Compute read tools.

- ``compute_list_instances``    -> instances under a project
- ``compute_get_instance``      -> single instance detail
- ``compute_list_disks``        -> disks under a project
- ``compute_get_disk``          -> single disk detail
- ``compute_list_platforms``    -> compute platforms (cpu / gpu families)

All read-only. Destructive verbs land in M3 behind NEBIUS_MCP_MODE=write.
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


def _resolve_parent(parent_id: str | None) -> str | None:
    return parent_id or _profile_parent_id()


def register(app: FastMCP) -> None:
    @app.tool(
        name="compute_list_instances",
        description=(
            "List compute instances (VMs) under a project. parent_id should be a "
            "project ID (e.g. 'project-...'). If omitted, uses parent-id from the "
            "active profile. Use compute_get_instance for full detail of a "
            "single VM."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def compute_list_instances(
        parent_id: Annotated[
            str | None,
            Field(description="Project ID. Omit to use active profile.", default=None),
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Items per page (capped to 200, default 50).", default=None, ge=1),
        ] = None,
        page_token: Annotated[
            str | None,
            Field(description="Opaque pagination token.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import InstanceServiceClient, ListInstancesRequest

        resolved = _resolve_parent(parent_id)
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(InstanceServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token

        resp = await safe(client.list(ListInstancesRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

    @app.tool(
        name="compute_get_instance",
        description=(
            "Get a single compute instance by ID. Returns metadata, spec "
            "(platform, preset, disks, network), and status (state, addresses)."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def compute_get_instance(
        id: Annotated[
            str,
            Field(description="Instance ID, e.g. 'computeinstance-...'.", min_length=1),
        ],
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import GetInstanceRequest, InstanceServiceClient

        client = service(InstanceServiceClient)
        resp = await safe(client.get(GetInstanceRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="compute_list_disks",
        description="List disks (block storage volumes) under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def compute_list_disks(
        parent_id: Annotated[
            str | None,
            Field(description="Project ID. Omit to use active profile.", default=None),
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Items per page (capped to 200, default 50).", default=None, ge=1),
        ] = None,
        page_token: Annotated[
            str | None,
            Field(description="Opaque pagination token.", default=None),
        ] = None,
        filter: Annotated[
            str | None,
            Field(description="Server-side filter expression.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import DiskServiceClient, ListDisksRequest

        resolved = _resolve_parent(parent_id)
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(DiskServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token
        if filter:
            kwargs["filter"] = filter

        resp = await safe(client.list(ListDisksRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

    @app.tool(
        name="compute_get_disk",
        description="Get a single disk by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def compute_get_disk(
        id: Annotated[str, Field(description="Disk ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import DiskServiceClient, GetDiskRequest

        client = service(DiskServiceClient)
        resp = await safe(client.get(GetDiskRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="compute_list_platforms",
        description=(
            "List available compute platforms (CPU and GPU families) in this "
            "tenant. Use to discover valid platform names for new instances. "
            "parent_id is a tenant ID; omit to use the active profile's "
            "parent-id (which may be a project — in that case the call may fail "
            "and you should call iam_whoami to get the tenant)."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def compute_list_platforms(
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
            Field(description="Opaque pagination token.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import ListPlatformsRequest, PlatformServiceClient

        resolved = _resolve_parent(parent_id)
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(PlatformServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token

        resp = await safe(client.list(ListPlatformsRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

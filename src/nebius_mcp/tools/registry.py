"""Container Registry read tools.

- ``registry_list``         -> registries under a project
- ``registry_get``          -> single registry by ID
- ``registry_list_images``  -> artifacts (image manifests) under a registry
- ``registry_get_image``    -> single artifact by ID

Note: pushing images themselves still goes through the Docker registry HTTP
API; this MCP only exposes registry / artifact metadata.
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
        name="registry_list",
        description="List container registries under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def registry_list(
        parent_id: Annotated[
            str | None,
            Field(description="Project ID. Omit to use active profile.", default=None),
        ] = None,
        page_size: Annotated[
            int | None, Field(description="Items per page.", default=None, ge=1)
        ] = None,
        page_token: Annotated[
            str | None, Field(description="Pagination token.", default=None)
        ] = None,
        filter: Annotated[str | None, Field(description="Filter expression.", default=None)] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.registry.v1 import ListRegistriesRequest, RegistryServiceClient

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(RegistryServiceClient)
        kwargs: dict[str, Any] = {"parent_id": resolved, "page_size": clamp_page_size(page_size)}
        if page_token:
            kwargs["page_token"] = page_token
        if filter:
            kwargs["filter"] = filter

        resp = await safe(client.list(ListRegistriesRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {"items": items, "next_page_token": resp.next_page_token or None, "parent_id": resolved}
        )

    @app.tool(
        name="registry_get",
        description="Get a single container registry by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def registry_get(
        id: Annotated[str, Field(description="Registry ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.registry.v1 import GetRegistryRequest, RegistryServiceClient

        client = service(RegistryServiceClient)
        resp = await safe(client.get(GetRegistryRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="registry_list_images",
        description=(
            "List artifacts (image manifests with tags + digests) under a "
            "registry. parent_id is the REGISTRY ID, not a project ID."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def registry_list_images(
        parent_id: Annotated[str, Field(description="Registry ID.", min_length=1)],
        page_size: Annotated[
            int | None, Field(description="Items per page.", default=None, ge=1)
        ] = None,
        page_token: Annotated[
            str | None, Field(description="Pagination token.", default=None)
        ] = None,
        filter: Annotated[str | None, Field(description="Filter expression.", default=None)] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.registry.v1 import ArtifactServiceClient, ListArtifactsRequest

        client = service(ArtifactServiceClient)
        kwargs: dict[str, Any] = {"parent_id": parent_id, "page_size": clamp_page_size(page_size)}
        if page_token:
            kwargs["page_token"] = page_token
        if filter:
            kwargs["filter"] = filter

        resp = await safe(client.list(ListArtifactsRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": parent_id,
            }
        )

    @app.tool(
        name="registry_get_image",
        description="Get a single artifact by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def registry_get_image(
        id: Annotated[str, Field(description="Artifact ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.registry.v1 import ArtifactServiceClient, GetArtifactRequest

        client = service(ArtifactServiceClient)
        resp = await safe(client.get(GetArtifactRequest(id=id)))
        return wrap(safe_proto(resp))

"""Managed Kubernetes (mk8s) read tools.

- ``k8s_list_clusters``                  -> clusters under a project
- ``k8s_get_cluster``                    -> single cluster detail
- ``k8s_list_node_groups``               -> node groups under a cluster (parent_id is cluster ID)
- ``k8s_get_node_group``                 -> single node-group detail
- ``k8s_list_control_plane_versions``    -> Kubernetes versions available for new clusters
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
        name="k8s_list_clusters",
        description="List managed Kubernetes clusters under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def k8s_list_clusters(
        parent_id: Annotated[
            str | None,
            Field(description="Project ID. Omit to use active profile.", default=None),
        ] = None,
        page_size: Annotated[
            int | None,
            Field(
                description="Items per page (capped to 200, default 50).",
                default=None,
                ge=1,
            ),
        ] = None,
        page_token: Annotated[
            str | None,
            Field(description="Opaque pagination token.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.mk8s.v1 import ClusterServiceClient, ListClustersRequest

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(ClusterServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token

        resp = await safe(client.list(ListClustersRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

    @app.tool(
        name="k8s_get_cluster",
        description=(
            "Get a single managed Kubernetes cluster by ID. Returns control-plane "
            "endpoints, version, audit-log spec, and status."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def k8s_get_cluster(
        id: Annotated[str, Field(description="Cluster ID, e.g. 'mk8scluster-...'.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.mk8s.v1 import ClusterServiceClient, GetClusterRequest

        client = service(ClusterServiceClient)
        resp = await safe(client.get(GetClusterRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="k8s_list_node_groups",
        description=(
            "List node groups under a cluster. parent_id must be a CLUSTER ID, not a project ID."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def k8s_list_node_groups(
        parent_id: Annotated[
            str,
            Field(description="Cluster ID, e.g. 'mk8scluster-...'.", min_length=1),
        ],
        page_size: Annotated[
            int | None,
            Field(
                description="Items per page (capped to 200, default 50).",
                default=None,
                ge=1,
            ),
        ] = None,
        page_token: Annotated[
            str | None,
            Field(description="Opaque pagination token.", default=None),
        ] = None,
    ) -> dict[str, Any]:
        from nebius.api.nebius.mk8s.v1 import ListNodeGroupsRequest, NodeGroupServiceClient

        client = service(NodeGroupServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": parent_id,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token

        resp = await safe(client.list(ListNodeGroupsRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": parent_id,
            }
        )

    @app.tool(
        name="k8s_get_node_group",
        description="Get a single node-group by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def k8s_get_node_group(
        id: Annotated[str, Field(description="Node-group ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.mk8s.v1 import GetNodeGroupRequest, NodeGroupServiceClient

        client = service(NodeGroupServiceClient)
        resp = await safe(client.get(GetNodeGroupRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="k8s_list_control_plane_versions",
        description=(
            "List Kubernetes versions available for new clusters and node-groups. "
            "Use to validate version strings before k8s_create_cluster."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def k8s_list_control_plane_versions() -> dict[str, Any]:
        from nebius.api.nebius.mk8s.v1 import (
            ClusterServiceClient,
            ListClusterControlPlaneVersionsRequest,
        )

        client = service(ClusterServiceClient)
        resp = await safe(
            client.list_control_plane_versions(ListClusterControlPlaneVersionsRequest())
        )
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap({"items": items})

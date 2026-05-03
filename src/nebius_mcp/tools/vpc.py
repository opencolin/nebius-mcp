"""VPC read tools.

- ``vpc_list_networks``         / ``vpc_get_network``
- ``vpc_list_subnets``          / ``vpc_get_subnet``
- ``vpc_list_security_groups``  / ``vpc_get_security_group``
- ``vpc_list_allocations``      / ``vpc_get_allocation``
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


def _list_kwargs(parent_id: str, page_size: int | None, page_token: str | None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"parent_id": parent_id, "page_size": clamp_page_size(page_size)}
    if page_token:
        kwargs["page_token"] = page_token
    return kwargs


def _empty(reason: str) -> dict[str, Any]:
    return wrap({"items": [], "next_page_token": None}, note=reason)


def register(app: FastMCP) -> None:
    @app.tool(
        name="vpc_list_networks",
        description="List VPC networks under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def vpc_list_networks(
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
    ) -> dict[str, Any]:
        from nebius.api.nebius.vpc.v1 import ListNetworksRequest, NetworkServiceClient

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            return _empty("No parent_id supplied and no parent-id in active profile.")
        client = service(NetworkServiceClient)
        resp = await safe(
            client.list(ListNetworksRequest(**_list_kwargs(resolved, page_size, page_token)))
        )
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {"items": items, "next_page_token": resp.next_page_token or None, "parent_id": resolved}
        )

    @app.tool(
        name="vpc_get_network",
        description="Get a single VPC network by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def vpc_get_network(
        id: Annotated[str, Field(description="Network ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.vpc.v1 import GetNetworkRequest, NetworkServiceClient

        client = service(NetworkServiceClient)
        resp = await safe(client.get(GetNetworkRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="vpc_list_subnets",
        description="List VPC subnets under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def vpc_list_subnets(
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
    ) -> dict[str, Any]:
        from nebius.api.nebius.vpc.v1 import ListSubnetsRequest, SubnetServiceClient

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            return _empty("No parent_id supplied and no parent-id in active profile.")
        client = service(SubnetServiceClient)
        resp = await safe(
            client.list(ListSubnetsRequest(**_list_kwargs(resolved, page_size, page_token)))
        )
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {"items": items, "next_page_token": resp.next_page_token or None, "parent_id": resolved}
        )

    @app.tool(
        name="vpc_get_subnet",
        description="Get a single VPC subnet by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def vpc_get_subnet(
        id: Annotated[str, Field(description="Subnet ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.vpc.v1 import GetSubnetRequest, SubnetServiceClient

        client = service(SubnetServiceClient)
        resp = await safe(client.get(GetSubnetRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="vpc_list_security_groups",
        description="List VPC security groups under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def vpc_list_security_groups(
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
    ) -> dict[str, Any]:
        from nebius.api.nebius.vpc.v1 import ListSecurityGroupsRequest, SecurityGroupServiceClient

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            return _empty("No parent_id supplied and no parent-id in active profile.")
        client = service(SecurityGroupServiceClient)
        resp = await safe(
            client.list(ListSecurityGroupsRequest(**_list_kwargs(resolved, page_size, page_token)))
        )
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {"items": items, "next_page_token": resp.next_page_token or None, "parent_id": resolved}
        )

    @app.tool(
        name="vpc_get_security_group",
        description="Get a single VPC security group by ID (includes rules).",
        annotations=READ_ANNOTATIONS,
    )
    async def vpc_get_security_group(
        id: Annotated[str, Field(description="Security-group ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.vpc.v1 import GetSecurityGroupRequest, SecurityGroupServiceClient

        client = service(SecurityGroupServiceClient)
        resp = await safe(client.get(GetSecurityGroupRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="vpc_list_allocations",
        description="List VPC IP allocations (public IP reservations) under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def vpc_list_allocations(
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
    ) -> dict[str, Any]:
        from nebius.api.nebius.vpc.v1 import AllocationServiceClient, ListAllocationsRequest

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            return _empty("No parent_id supplied and no parent-id in active profile.")
        client = service(AllocationServiceClient)
        resp = await safe(
            client.list(ListAllocationsRequest(**_list_kwargs(resolved, page_size, page_token)))
        )
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {"items": items, "next_page_token": resp.next_page_token or None, "parent_id": resolved}
        )

    @app.tool(
        name="vpc_get_allocation",
        description="Get a single VPC IP allocation by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def vpc_get_allocation(
        id: Annotated[str, Field(description="Allocation ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.vpc.v1 import AllocationServiceClient, GetAllocationRequest

        client = service(AllocationServiceClient)
        resp = await safe(client.get(GetAllocationRequest(id=id)))
        return wrap(safe_proto(resp))

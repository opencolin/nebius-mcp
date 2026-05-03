"""AI Endpoints read tools.

- ``ai_list_endpoints``       -> endpoints under a project
- ``ai_get_endpoint``         -> single endpoint by ID
- ``ai_get_endpoint_by_name`` -> single endpoint by parent_id + name

KNOWN GAPS (no SDK RPC, surface in M5+ via CLI fallback):
- endpoint update
- endpoint logs (tail)
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
from ._ops_helpers import register_delete_tool, register_state_tool

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
        name="ai_list_endpoints",
        description="List Nebius AI Endpoints under a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def ai_list_endpoints(
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
        from nebius.api.nebius.ai.v1 import EndpointServiceClient, ListEndpointsRequest

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            return wrap(
                {"items": [], "next_page_token": None},
                note="No parent_id supplied and no parent-id in active profile.",
            )

        client = service(EndpointServiceClient)
        kwargs: dict[str, Any] = {
            "parent_id": resolved,
            "page_size": clamp_page_size(page_size),
        }
        if page_token:
            kwargs["page_token"] = page_token

        resp = await safe(client.list(ListEndpointsRequest(**kwargs)))
        items = [safe_proto(it) for it in (resp.items or [])]
        return wrap(
            {
                "items": items,
                "next_page_token": resp.next_page_token or None,
                "parent_id": resolved,
            }
        )

    @app.tool(
        name="ai_get_endpoint",
        description="Get a single AI Endpoint by ID.",
        annotations=READ_ANNOTATIONS,
    )
    async def ai_get_endpoint(
        id: Annotated[str, Field(description="Endpoint ID.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.ai.v1 import EndpointServiceClient, GetEndpointRequest

        client = service(EndpointServiceClient)
        resp = await safe(client.get(GetEndpointRequest(id=id)))
        return wrap(safe_proto(resp))

    @app.tool(
        name="ai_get_endpoint_by_name",
        description="Look up a single AI Endpoint by name within a project.",
        annotations=READ_ANNOTATIONS,
    )
    async def ai_get_endpoint_by_name(
        parent_id: Annotated[str, Field(description="Project ID.", min_length=1)],
        name: Annotated[str, Field(description="Endpoint name.", min_length=1)],
    ) -> dict[str, Any]:
        from nebius.api.nebius.ai.v1 import EndpointServiceClient, GetEndpointByNameRequest

        client = service(EndpointServiceClient)
        resp = await safe(
            client.get_by_name(GetEndpointByNameRequest(parent_id=parent_id, name=name))
        )
        return wrap(safe_proto(resp))

    from nebius.api.nebius.ai.v1 import (
        DeleteEndpointRequest,
        StartEndpointRequest,
        StopEndpointRequest,
    )
    from nebius.api.nebius.ai.v1 import (
        EndpointServiceClient as _EndpointServiceClient,
    )

    register_state_tool(
        app,
        tool_name="ai_start_endpoint",
        description="Start a stopped AI Endpoint. Reversible; gated by write mode.",
        client_cls=_EndpointServiceClient,
        request_cls=StartEndpointRequest,
        method_name="start",
        id_description="Endpoint ID.",
    )
    register_state_tool(
        app,
        tool_name="ai_stop_endpoint",
        description="Stop a running AI Endpoint. Reversible; gated by write mode.",
        client_cls=_EndpointServiceClient,
        request_cls=StopEndpointRequest,
        method_name="stop",
        id_description="Endpoint ID.",
    )
    register_delete_tool(
        app,
        tool_name="ai_delete_endpoint",
        resource_label="AI Endpoint",
        client_cls=_EndpointServiceClient,
        request_cls=DeleteEndpointRequest,
        id_description="Endpoint ID.",
    )

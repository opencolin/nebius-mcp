"""Universal resource access across every Nebius service in the SDK.

The hand-written modules (compute, k8s, vpc, ...) cover the resources an agent
touches constantly, with rich parameters and skill-derived validation. They
deliberately do not cover all 59 resource types the SDK exposes: one MCP tool
per resource per verb would be ~300 tools, which measurably degrades tool
selection in every client.

These six tools close that gap. They are driven by :mod:`nebius_mcp.catalog`,
so anything the installed SDK can reach is reachable here — including services
that had no tools at all before (object storage, DNS, KMS, quotas, managed
PostgreSQL, audit, capacity, tunnels).

Trade-off: generic tools take a ``resource_type`` discriminator instead of
resource-shaped arguments, so the model must call ``nebius_list_resource_types``
(or read the enum in the schema) to discover what is addressable. That is the
price of bounded tool count.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from .. import catalog
from ..auth import resolve_credentials
from ..client import service
from ..confirm import preview_or_execute, require_write
from ..errors import safe
from ..operation import DEFAULT_WAIT_TIMEOUT_SECONDS, maybe_wait
from ..pagination import clamp_page_size
from ..sanitize import safe_proto, wrap
from ._ops_helpers import COMPOSITE_ACTION_ANNOTATIONS, DESTRUCTIVE_ANNOTATIONS

READ_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

_KEYS = tuple(spec.key for spec in catalog.RESOURCES)
ResourceType = Literal[_KEYS]  # type: ignore[valid-type]

# Lifecycle verbs the action tool will dispatch. Shared with the catalog, which
# needs to know which verbs are addressed by a bare ``id`` to work out whether a
# request can be built at all.
_ACTIONS = catalog.ACTION_VERBS
ActionName = Literal[_ACTIONS]  # type: ignore[valid-type]

# Actions that destroy work rather than just flipping state. Cancelling an AI
# training job or a running export discards everything it has done so far and
# cannot be resumed, so these take the same two-step confirm as a delete.
_IRREVERSIBLE_ACTIONS = frozenset({"cancel"})


# Resources these hand-written modules cover more richly than the generic layer.
# Consulted only when a verb exists in the SDK but its request cannot be built
# from the generic shape, so the caller is pointed somewhere that works instead
# of at a dead end — and, just as usefully, is told plainly when nothing else
# covers the resource. Guarded by test_dedicated_tool_hints_name_real_tools.
_DEDICATED_TOOLS: dict[str, tuple[str, ...]] = {
    "ai.endpoint": ("ai_list_endpoints", "ai_get_endpoint", "ai_get_endpoint_by_name"),
    "compute.instance": (
        "compute_list_instances",
        "compute_get_instance",
        "compute_create_instance",
        "compute_start_instance",
        "compute_stop_instance",
        "compute_delete_instance",
    ),
    "compute.disk": ("compute_list_disks", "compute_get_disk", "compute_delete_disk"),
    "compute.platform": ("compute_list_platforms",),
    "mk8s.cluster": ("k8s_list_clusters", "k8s_get_cluster", "k8s_list_control_plane_versions"),
    "mk8s.node_group": ("k8s_list_node_groups", "k8s_get_node_group"),
    "vpc.network": ("vpc_list_networks", "vpc_get_network"),
    "vpc.subnet": ("vpc_list_subnets", "vpc_get_subnet"),
    "vpc.security_group": ("vpc_list_security_groups", "vpc_get_security_group"),
    "vpc.allocation": ("vpc_list_allocations", "vpc_get_allocation"),
    "iam.project": ("iam_list_projects", "iam_get_project"),
    "registry.registry": ("registry_list", "registry_get"),
    "registry.artifact": ("registry_list_images", "registry_get_image"),
    "mysterybox.secret": ("secrets_list", "secrets_get"),
    "mysterybox.secret_version": ("secrets_list_versions", "secrets_reveal_payload"),
}


def _dedicated_tool_hint(resource_type: str) -> str:
    tools = _DEDICATED_TOOLS.get(resource_type)
    if tools:
        return f"Try a dedicated tool for this resource: {', '.join(tools)}."
    return (
        f"No dedicated tool covers {resource_type}, so this operation needs richer "
        "parameters than any tool on this server accepts."
    )


# Verbs these tools actually dispatch. catalog.verbs() is deliberately wider —
# it also reports verbs like create/update that only a dedicated tool covers —
# so an error message from *this* module intersects with it before advising.
_GENERIC_VERBS = frozenset({"list", "get", "get_by_name", "delete", *_ACTIONS})


def _available(resource_type: str) -> str:
    return ", ".join(sorted(catalog.verbs(resource_type) & _GENERIC_VERBS)) or "none"


def _unreachable_message(spec: catalog.ResourceSpec, resource_type: str, verb: str) -> str:
    """Explain a verb that exists in the SDK but not in a shape we can build.

    Saying "does not support 'delete'" here would be false — the RPC is there.
    What is missing is a way to express the request through tools that address a
    resource by one string ID, so the message says exactly that, quotes the
    SDK's own construction error, and names the request's real fields.
    """
    request_cls = catalog.request_class(resource_type, verb)
    reason = catalog.unreachable_reason(resource_type, verb)
    fields = ", ".join(sorted(catalog.request_fields(request_cls))) if request_cls else ""
    return (
        f"{spec.label} ({resource_type}) has {verb!r} in nebius SDK {_sdk_version()}, but it is "
        f"not reachable through the generic tools: they address a resource by a single string "
        f"id, and building the request failed with {reason}. Its request fields are: {fields}. "
        f"{_dedicated_tool_hint(resource_type)} "
        f"Available operations: {_available(resource_type)}."
    )


def _require(resource_type: str, verb: str) -> type:
    spec = catalog.BY_KEY.get(resource_type)
    if spec is None:
        raise ToolError(
            f"Unknown resource_type {resource_type!r}. "
            "Call nebius_list_resource_types to see valid values."
        )
    request_cls = catalog.request_class(resource_type, verb)
    if request_cls is None:
        raise ToolError(
            f"{spec.label} ({resource_type}) does not support {verb!r} in nebius SDK "
            f"{_sdk_version()}. Available operations: {_available(resource_type)}."
        )
    # The RPC exists but the catalog withheld it: its request needs more than an ID.
    if not catalog.supports(resource_type, verb):
        raise ToolError(_unreachable_message(spec, resource_type, verb))
    return request_cls


def _sdk_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("nebius")
    except PackageNotFoundError:  # pragma: no cover
        return "unknown"


def _profile_parent_id() -> str | None:
    return resolve_credentials().parent_id


def register(app: FastMCP) -> None:
    @app.tool(
        name="nebius_list_resource_types",
        description=(
            "List every Nebius resource type reachable through the generic "
            "nebius_resource_* tools, with the operations each supports and what "
            "parent_id means for it. Call this first when you need a service that "
            "has no dedicated tool (object storage, DNS, KMS, quotas, managed "
            "PostgreSQL, audit, capacity, tunnels, IAM service accounts, ...). "
            "Read-only, makes no API calls."
        ),
        annotations={**READ_ANNOTATIONS, "openWorldHint": False},
    )
    def nebius_list_resource_types(
        domain: Annotated[
            str | None,
            Field(
                description="Filter by domain prefix, e.g. 'storage', 'iam', 'vpc'.",
                default=None,
            ),
        ] = None,
    ) -> dict[str, Any]:
        items = [
            catalog.describe(spec)
            for spec in catalog.RESOURCES
            if domain is None or spec.key.split(".", 1)[0] == domain
        ]
        return wrap(
            {
                "resource_types": items,
                "count": len(items),
                "nebius_sdk_version": _sdk_version(),
            },
            note=(
                "parent_id_means is load-bearing: several resources are parented by "
                "something other than a project (node groups by cluster, security rules "
                "by security group, access keys by service account, secret versions by "
                "secret). Passing a project ID to those returns an empty list or an error."
            ),
        )

    @app.tool(
        name="nebius_resource_list",
        description=(
            "List resources of any Nebius type. Use nebius_list_resource_types to "
            "discover valid resource_type values and what parent_id must be for "
            "each. Prefer a dedicated tool (compute_list_instances, k8s_list_clusters, "
            "...) when one exists — they return richer, validated results."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def nebius_resource_list(
        resource_type: Annotated[
            ResourceType,
            Field(description="Resource type key, e.g. 'storage.bucket'."),
        ],
        parent_id: Annotated[
            str | None,
            Field(
                description=(
                    "Parent scope. Meaning varies by resource — see "
                    "nebius_list_resource_types. Omit to use the active profile's parent-id."
                ),
                default=None,
            ),
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Items per page (capped to 200, default 50).", default=None, ge=1),
        ] = None,
        page_token: Annotated[
            str | None, Field(description="Opaque pagination token.", default=None)
        ] = None,
        filter: Annotated[
            str | None,
            Field(
                description="Server-side filter expression. Ignored if unsupported.",
                default=None,
            ),
        ] = None,
    ) -> dict[str, Any]:
        spec = catalog.BY_KEY[resource_type]
        request_cls = _require(resource_type, "list")
        fields = catalog.request_fields(request_cls)

        resolved = parent_id or _profile_parent_id()
        kwargs: dict[str, Any] = {}

        # Most list requests scope by parent_id; OperationService scopes by resource_id.
        scope_field = "parent_id" if "parent_id" in fields else "resource_id"
        if scope_field in fields:
            if not resolved:
                return wrap(
                    {"items": [], "next_page_token": None},
                    note=(
                        f"{spec.label} requires {scope_field} ({spec.parent}) and none was "
                        "supplied or found in the active profile."
                    ),
                )
            kwargs[scope_field] = resolved
        if "page_size" in fields:
            kwargs["page_size"] = clamp_page_size(page_size)
        if page_token and "page_token" in fields:
            kwargs["page_token"] = page_token
        if filter and "filter" in fields:
            kwargs["filter"] = filter

        client: Any = service(catalog.client_class(resource_type))
        resp = await safe(client.list(request_cls(**kwargs)))
        collection = catalog.list_items_field(resource_type) or "items"
        items = [safe_proto(it) for it in (getattr(resp, collection, None) or [])]
        return wrap(
            {
                "resource_type": resource_type,
                "items": items,
                "next_page_token": getattr(resp, "next_page_token", None) or None,
                scope_field: kwargs.get(scope_field),
            }
        )

    @app.tool(
        name="nebius_resource_get",
        description=(
            "Get a single resource of any Nebius type by ID. Use "
            "nebius_list_resource_types to discover valid resource_type values."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def nebius_resource_get(
        resource_type: Annotated[
            ResourceType, Field(description="Resource type key, e.g. 'storage.bucket'.")
        ],
        id: Annotated[str, Field(description="Resource ID.", min_length=1)],
    ) -> dict[str, Any]:
        request_cls = _require(resource_type, "get")
        client: Any = service(catalog.client_class(resource_type))
        resp = await safe(client.get(request_cls(id=id)))
        return wrap({"resource_type": resource_type, "resource": safe_proto(resp)})

    @app.tool(
        name="nebius_resource_get_by_name",
        description=(
            "Get a single resource of any Nebius type by its name within a parent "
            "scope. Useful when you know a human-readable name but not the ID."
        ),
        annotations=READ_ANNOTATIONS,
    )
    async def nebius_resource_get_by_name(
        resource_type: Annotated[
            ResourceType, Field(description="Resource type key, e.g. 'storage.bucket'.")
        ],
        name: Annotated[str, Field(description="Resource name.", min_length=1)],
        parent_id: Annotated[
            str | None,
            Field(
                description="Parent scope; omit to use the active profile's parent-id.",
                default=None,
            ),
        ] = None,
    ) -> dict[str, Any]:
        spec = catalog.BY_KEY[resource_type]
        request_cls = _require(resource_type, "get_by_name")
        resolved = parent_id or _profile_parent_id()
        if not resolved:
            raise ToolError(
                f"nebius_resource_get_by_name: parent_id is required for {spec.label} "
                f"({spec.parent}) and none is set in the active profile."
            )
        client: Any = service(catalog.client_class(resource_type))
        resp = await safe(client.get_by_name(request_cls(parent_id=resolved, name=name)))
        return wrap({"resource_type": resource_type, "resource": safe_proto(resp)})

    @app.tool(
        name="nebius_resource_delete",
        description=(
            "Delete a resource of any Nebius type. IRREVERSIBLE. First call returns "
            "a preview and a single-use confirm_token (expires in 120s); call again "
            "with the token to execute. Gated by write mode."
        ),
        annotations=DESTRUCTIVE_ANNOTATIONS,
    )
    async def nebius_resource_delete(
        resource_type: Annotated[
            ResourceType, Field(description="Resource type key, e.g. 'storage.bucket'.")
        ],
        id: Annotated[str, Field(description="Resource ID.", min_length=1)],
        confirm_token: Annotated[
            str | None, Field(description="Token from a prior dry-run call.", default=None)
        ] = None,
        wait: Annotated[
            bool, Field(description="Block until deletion completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        # Check the mode before the verb, so a read-only server answers
        # "write mode is disabled" rather than doubling as an oracle for which
        # SDK operations exist. Validate the verb before issuing a token, so a
        # dry run cannot hand back a token that is guaranteed to fail on use.
        require_write("nebius_resource_delete")
        spec = catalog.BY_KEY[resource_type]
        request_cls = _require(resource_type, "delete")

        gate = preview_or_execute(
            tool="nebius_resource_delete",
            args={"resource_type": resource_type, "id": id},
            confirm_token=confirm_token,
            preview={
                "action": f"Delete {spec.label} {id}",
                "resource_type": resource_type,
                "id": id,
            },
        )
        if gate is not None:
            return gate  # type: ignore[return-value]

        client: Any = service(catalog.client_class(resource_type))
        op = await safe(client.delete(request_cls(id=id)))
        return wrap(await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds))

    @app.tool(
        name="nebius_resource_action",
        description=(
            "Run a lifecycle action (start, stop, restart, resume, activate, "
            "deactivate, undelete, cancel) on any Nebius resource that supports "
            "it. Gated by write mode. 'cancel' discards in-flight work and so "
            "additionally requires the two-step confirm_token flow. The "
            "annotations on this tool describe the worst verb it accepts, not "
            "the verb you pass: destructive because of 'cancel', non-idempotent "
            "because of 'restart'. Use nebius_list_resource_types to see which "
            "actions a resource supports."
        ),
        annotations=COMPOSITE_ACTION_ANNOTATIONS,
    )
    async def nebius_resource_action(
        resource_type: Annotated[
            ResourceType, Field(description="Resource type key, e.g. 'ai.endpoint'.")
        ],
        action: Annotated[ActionName, Field(description="Lifecycle action to perform.")],
        id: Annotated[str, Field(description="Resource ID.", min_length=1)],
        confirm_token: Annotated[
            str | None,
            Field(
                description="Token from a prior dry-run call. Required for 'cancel'.",
                default=None,
            ),
        ] = None,
        wait: Annotated[
            bool, Field(description="Block until the operation completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        require_write("nebius_resource_action")
        spec = catalog.BY_KEY[resource_type]
        request_cls = _require(resource_type, action)

        if action in _IRREVERSIBLE_ACTIONS:
            gate = preview_or_execute(
                tool="nebius_resource_action",
                args={"resource_type": resource_type, "action": action, "id": id},
                confirm_token=confirm_token,
                preview={
                    "action": f"Cancel {spec.label} {id} — in-flight work is discarded",
                    "resource_type": resource_type,
                    "id": id,
                },
            )
            if gate is not None:
                return gate  # type: ignore[return-value]

        client: Any = service(catalog.client_class(resource_type))
        method = getattr(client, action)
        op = await safe(method(request_cls(id=id)))
        return wrap(await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds))

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
from ..confirm import preview_or_execute, require_write
from ..errors import safe
from ..operation import DEFAULT_WAIT_TIMEOUT_SECONDS, maybe_wait
from ..pagination import clamp_page_size
from ..sanitize import safe_proto, wrap
from ..validation import (
    gib_to_bytes,
    validate_boot_disk_size,
    validate_disk_type,
)
from ._ops_helpers import CREATE_ANNOTATIONS, DESTRUCTIVE_ANNOTATIONS, STATE_ANNOTATIONS

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
        name="compute_start_instance",
        description=(
            "Start a stopped compute instance. Reversible; gated by write mode "
            "(NEBIUS_MCP_MODE=write)."
        ),
        annotations=STATE_ANNOTATIONS,
    )
    async def compute_start_instance(
        id: Annotated[str, Field(description="Instance ID.", min_length=1)],
        wait: Annotated[
            bool, Field(description="Block until operation completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import InstanceServiceClient, StartInstanceRequest

        require_write("compute_start_instance")
        client = service(InstanceServiceClient)
        op = await safe(client.start(StartInstanceRequest(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)

    @app.tool(
        name="compute_stop_instance",
        description=("Stop a running compute instance. Reversible; gated by write mode."),
        annotations=STATE_ANNOTATIONS,
    )
    async def compute_stop_instance(
        id: Annotated[str, Field(description="Instance ID.", min_length=1)],
        wait: Annotated[
            bool, Field(description="Block until operation completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import InstanceServiceClient, StopInstanceRequest

        require_write("compute_stop_instance")
        client = service(InstanceServiceClient)
        op = await safe(client.stop(StopInstanceRequest(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)

    @app.tool(
        name="compute_delete_instance",
        description=(
            "Delete a compute instance. IRREVERSIBLE. First call returns a "
            "preview and a single-use confirm_token (expires in 120s); call "
            "again with the token to execute. Gated by write mode."
        ),
        annotations=DESTRUCTIVE_ANNOTATIONS,
    )
    async def compute_delete_instance(
        id: Annotated[str, Field(description="Instance ID.", min_length=1)],
        confirm_token: Annotated[
            str | None,
            Field(description="Token from a prior dry-run call.", default=None),
        ] = None,
        wait: Annotated[
            bool, Field(description="Block until deletion completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import DeleteInstanceRequest, InstanceServiceClient

        gate = preview_or_execute(
            tool="compute_delete_instance",
            args={"id": id},
            confirm_token=confirm_token,
            preview={"action": f"Delete compute instance {id}", "id": id},
        )
        if gate is not None:
            return gate  # type: ignore[return-value]

        client = service(InstanceServiceClient)
        op = await safe(client.delete(DeleteInstanceRequest(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)

    @app.tool(
        name="compute_delete_disk",
        description=("Delete a disk. IRREVERSIBLE. Two-step confirm; gated by write mode."),
        annotations=DESTRUCTIVE_ANNOTATIONS,
    )
    async def compute_delete_disk(
        id: Annotated[str, Field(description="Disk ID.", min_length=1)],
        confirm_token: Annotated[
            str | None,
            Field(description="Token from a prior dry-run call.", default=None),
        ] = None,
        wait: Annotated[
            bool, Field(description="Block until deletion completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.compute.v1 import DeleteDiskRequest, DiskServiceClient

        gate = preview_or_execute(
            tool="compute_delete_disk",
            args={"id": id},
            confirm_token=confirm_token,
            preview={"action": f"Delete disk {id}", "id": id},
        )
        if gate is not None:
            return gate  # type: ignore[return-value]

        client = service(DiskServiceClient)
        op = await safe(client.delete(DeleteDiskRequest(id=id)))
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)

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

    @app.tool(
        name="compute_create_instance",
        description=(
            "Create a compute VM instance. INCURS COST. First call returns a "
            "preview and a single-use confirm_token; call again with the token "
            "to execute. Boot disk minimum is 50 GiB. Disk types use underscores "
            "(network_ssd, not network-ssd). Default SSH user is 'nebius'. "
            "Gated by write mode."
        ),
        annotations=CREATE_ANNOTATIONS,
    )
    async def compute_create_instance(
        name: Annotated[
            str, Field(description="Instance name (must be unique in project).", min_length=1)
        ],
        platform: Annotated[
            str,
            Field(description="Platform name. Discover via compute_list_platforms.", min_length=1),
        ],
        preset: Annotated[
            str,
            Field(description="Preset within the platform, e.g. '4vcpu-16gb'.", min_length=1),
        ],
        image_family: Annotated[
            str,
            Field(description="Source image family, e.g. 'ubuntu22.04-cuda12'.", min_length=1),
        ],
        subnet_id: Annotated[str, Field(description="VPC subnet ID.", min_length=1)],
        ssh_public_key: Annotated[
            str,
            Field(
                description="SSH public key, full line. Authorized for user 'nebius'.",
                min_length=1,
            ),
        ],
        parent_id: Annotated[
            str | None,
            Field(description="Project ID. Omit to use active profile.", default=None),
        ] = None,
        boot_disk_size_gib: Annotated[
            int,
            Field(description="Boot disk size in GiB (>= 50).", default=50, ge=50),
        ] = 50,
        boot_disk_type: Annotated[
            str,
            Field(description="Disk type. network_ssd / network_hdd / etc.", default="network_ssd"),
        ] = "network_ssd",
        public_ip: Annotated[
            bool,
            Field(description="Assign an ephemeral public IP.", default=False),
        ] = False,
        gpu_cluster_id: Annotated[
            str | None,
            Field(description="Optional GPU cluster ID.", default=None),
        ] = None,
        service_account_id: Annotated[
            str | None,
            Field(description="Optional service-account ID to attach.", default=None),
        ] = None,
        confirm_token: Annotated[
            str | None,
            Field(description="Token from a prior dry-run call.", default=None),
        ] = None,
        wait: Annotated[
            bool, Field(description="Block until creation completes.", default=True)
        ] = True,
        timeout_seconds: Annotated[
            int,
            Field(description="Wait timeout.", default=DEFAULT_WAIT_TIMEOUT_SECONDS, ge=1),
        ] = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        from nebius.api.nebius.common.v1 import ResourceMetadata
        from nebius.api.nebius.compute.v1 import (
            AttachedDiskSpec,
            CreateInstanceRequest,
            DiskSpec,
            InstanceGpuClusterSpec,
            InstanceServiceClient,
            InstanceSpec,
            ManagedDisk,
            NetworkInterfaceSpec,
            PublicIPAddress,
            ResourcesSpec,
            SourceImageFamily,
        )

        # Validate before issuing token (so the preview doesn't expose what
        # would have been a guaranteed-fail request).
        validate_disk_type(boot_disk_type)
        size_bytes = gib_to_bytes(boot_disk_size_gib)
        validate_boot_disk_size(size_bytes, image_family=image_family)

        resolved = parent_id or _profile_parent_id()
        if not resolved:
            from fastmcp.exceptions import ToolError

            raise ToolError(
                "compute_create_instance: parent_id is required (project ID), and no "
                "parent-id is set in the active profile."
            )

        cloud_init = (
            "#cloud-config\n"
            "users:\n"
            "  - name: nebius\n"
            "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
            "    shell: /bin/bash\n"
            "    ssh_authorized_keys:\n"
            f"      - {ssh_public_key.strip()}\n"
        )

        args = {
            "name": name,
            "parent_id": resolved,
            "platform": platform,
            "preset": preset,
            "image_family": image_family,
            "subnet_id": subnet_id,
            "boot_disk_size_gib": boot_disk_size_gib,
            "boot_disk_type": boot_disk_type,
            "public_ip": public_ip,
            "gpu_cluster_id": gpu_cluster_id,
            "service_account_id": service_account_id,
        }
        gate = preview_or_execute(
            tool="compute_create_instance",
            args=args,
            confirm_token=confirm_token,
            preview={
                "action": f"Create instance {name!r} in project {resolved}",
                "platform": platform,
                "preset": preset,
                "image_family": image_family,
                "boot_disk_size_gib": boot_disk_size_gib,
                "subnet_id": subnet_id,
                "public_ip": public_ip,
            },
        )
        if gate is not None:
            return gate  # type: ignore[return-value]

        require_write("compute_create_instance")

        boot_disk = AttachedDiskSpec(
            attach_mode=AttachedDiskSpec.AttachMode.READ_WRITE,
            managed_disk=ManagedDisk(
                spec=DiskSpec(
                    size_bytes=size_bytes,
                    type=getattr(DiskSpec.DiskType, boot_disk_type.upper()),
                    source_image_family=SourceImageFamily(image_family=image_family),
                )
            ),
        )

        nic_kwargs: dict[str, Any] = {"subnet_id": subnet_id, "name": "eth0"}
        if public_ip:
            nic_kwargs["public_ip_address"] = PublicIPAddress(static=False)
        nic = NetworkInterfaceSpec(**nic_kwargs)

        spec_kwargs: dict[str, Any] = {
            "resources": ResourcesSpec(platform=platform, preset=preset),
            "boot_disk": boot_disk,
            "network_interfaces": [nic],
            "cloud_init_user_data": cloud_init,
        }
        if gpu_cluster_id:
            spec_kwargs["gpu_cluster"] = InstanceGpuClusterSpec(id=gpu_cluster_id)
        if service_account_id:
            spec_kwargs["service_account_id"] = service_account_id

        client = service(InstanceServiceClient)
        op = await safe(
            client.create(
                CreateInstanceRequest(
                    metadata=ResourceMetadata(name=name, parent_id=resolved),
                    spec=InstanceSpec(**spec_kwargs),
                )
            )
        )
        summary = await maybe_wait(op, wait=wait, timeout_seconds=timeout_seconds)
        return wrap(summary)
